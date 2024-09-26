(ns tiny-auth.phone-number.core
  (:require [ring.util.http-response :refer [ok]]
            [tiny-auth.third-party.utils :refer [session-transaction]]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn create-account-with-phone-number
  [config {:keys [phone-number session-id session-language agent additional-data password]}]
  (let [snapshot ((:db config) (:conn config))
        additional-data (or additional-data "")]
    (f/attempt-all
     [v-phone-number (validators/phone phone-number)
      v-session-id (validators/string->uuid session-id "session-id")
      v-session-language (validators/language-code config session-language)
      _ (validators/string-size additional-data 1024 "additional-data")
      v-additional-data (validators/json-string additional-data)
      v-password (if password (validators/password-strength password))]
     (let [user (db-user/get-by-id config snapshot :user/phone-number phone-number)
           response-existing-user {:success true
                                   :internal-user-id (:app/uuid user)
                                   :access-token (utils/generate-token
                                                  config
                                                  user
                                                  v-session-id)}]
       (cond
         (and (:user/confirmed user)
              (:user/password-hash user))
         {:response :validators/user-uniqueness
          :transaction []}

         (:user/confirmed user)
         {:response (ok (assoc response-existing-user :confirmed true))
          :transaction []}

         (:app/uuid user)
         {:response (ok response-existing-user)
          :transaction []}

         :else
         (let [code (utils/generate-phone-confirmation-code 4)
               create-user (db-user/creation-transaction
                            (merge {:phone-number v-phone-number
                                    :confirmation-code code
                                    :additional-data v-additional-data}
                                   (if v-password {:password v-password} {})))
               user (first create-user)
               hooks-result ((:create-account-with-phone-number-hooks config)
                                  user
                                  v-session-language
                                  agent)
               token (utils/generate-token config user v-session-id)]
           {:response (ok {:success true
                           :internal-user-id (:app/uuid user)
                           :access-token token})
            :transaction (concat
                          create-user
                          (:transaction hooks-result)
                          (db-session/creation-transaction
                           {:sync-status :user-session.sync-status/needs-counter-zeroing
                            :session-id v-session-id
                            :session-language v-session-language
                            :user user}))
            :hooks-transaction (:hooks-transaction hooks-result)})))
     (f/when-failed [e] (:message e)))))

(defn resend-confirmation-sms
  [config {:keys [phone-number session-language agent]}]
  (f/attempt-all
   [v-session-language (validators/language-code config session-language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/phone-number phone-number)
         update-code ((:get-update-code-fn config) :create-account-with-phone-number)
         update-code-result (update-code
                             user
                             nil
                             v-session-language
                             snapshot
                             nil
                             agent)]
     (cond
       (nil? (:app/uuid user))
       {:response :auth-confirm/bad-auth
        :transaction []}

       (:user/confirmed user)
       {:response :auth-confirm/already-confirmed
        :transaction []}

       (not (:success update-code-result))
       {:response :auth-confirm/too-many-sms
        :transaction []}

       :else
       {:response (ok {:success true})
        :transaction (:transaction update-code-result)
        :hooks-transaction (:hooks-transaction update-code-result)}))
   (f/when-failed [e] (:message e))))

(defn add-password 
  [_config {:keys [user password]}]
  (f/attempt-all
   [v-password (validators/password-strength password)] 
   (let [encrypted-password (utils/encrypt-password v-password)]
     (cond
       (:user/password-hash user)
       {:response :auth-add-password/password-exists
        :transaction []}
       (not (:user/confirmed user))
       {:response :auth-login-email/not-confirmed
        :transaction []}
       :else
       {:response (ok {:success true})
        :transaction [[:db/cas (:db/id user) :user/password-hash nil encrypted-password]]}))
   (f/when-failed [e] (:message e))))

(defn add-email
  [config {:keys [user email]}]
  (let [snapshot ((:db config) (:conn config))]
    (f/attempt-all
     [_ (validators/user-uniqueness-email config email snapshot)
      v-email (validators/email config email)]
     (let [last-email-update (:user/last-email-update user)]
       (cond
         (nil? (:app/uuid user))
         {:response :auth-add-password/bad-auth-phone-number
          :transaction []}

         (not (:user/password-hash user))
         {:response :auth-add-password/password-exists
          :transaction []}

         (not (:user/confirmed user))
         {:response :auth-login-email/not-confirmed
          :transaction []}

         (and last-email-update
              (not (utils/check-email-frequency config last-email-update)))
         {:response :auth-phone-number-add-email/too-many
          :transaction []}

         :else
         (let [hooks-result ((:add-email-hooks config)
                             snapshot
                             user
                             v-email)]
           {:response (ok {:success true})
            :transaction (concat
                          (db-user/update-email-transaction user v-email)
                          (:transaction hooks-result))
            :hooks-transaction (:hooks-transaction hooks-result)})))
     (f/when-failed [e] (:message e)))))

(defn login-with-phone-number
  [config {:keys [phone-number password session-id session-language]}]
  (f/attempt-all
   [v-session-id (validators/string->uuid session-id "session-id")
    v-session-language (validators/language-code config session-language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/phone-number phone-number)]
     (cond
       (nil? user)
       {:response :auth-login-phone-number/bad-auth
        :transaction []}

       (not (utils/check-login-frequency config user))
       {:response :auth-login-email/too-many-failures
        :transaction []}

       (not (:user/confirmed user))
       {:response :auth-login-email/not-confirmed
        :data {"internal-user-id" (:app/uuid user)}
        :transaction []}

       (nil? (:user/password-hash user))
       {:response :auth-login-phone-number/password-doesnt-exist
        :data {"internal-user-id" (:app/uuid user)}
        :transaction []}

       (not (utils/check-password password (:user/password-hash user)))
       {:response :auth-login-phone-number/bad-auth
        :transaction (db-user/failed-login-transaction user)}

       (:user/deactivated user)
       {:response :auth-login-email/deactivated-user
        :data {"internal-user-id" (:app/uuid user)}
        :transaction []}

       :else
       (let [custom-log-in-data (when-let [get-custom-log-in-data (:get-custom-log-in-data config)]
                                  (get-custom-log-in-data snapshot user))
             log-in-response (db-user/login-success-response
                              config
                              snapshot
                              user
                              v-session-id)]
         {:response (ok (merge log-in-response custom-log-in-data))
          :transaction (concat
                        (db-user/login-transaction user)
                        (session-transaction
                         {:snapshot snapshot
                          :config config
                          :session-id v-session-id
                          :user user
                          :session-language v-session-language}))})))
   (f/when-failed [e] (:message e))))
