(ns tiny-auth.phone-number.core
  (:require [ring.util.http-response :refer [ok]]
            [tiny-auth.third-party.utils :refer [session-transaction]]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn create-account-with-phone-number
  [config {:keys [phone-number session-id session-language agent]}]
  (let [snapshot ((:db config) (:conn config))]
    (f/attempt-all
     [v-phone-number (validators/phone phone-number)
      v-session-id (validators/string->uuid session-id "session-id")
      v-session-language (validators/language-code session-language)]
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
         (let [update-code ((:get-update-code-fn config) :create-account-with-phone-number)
               update-code-tx (update-code
                               user
                               v-session-id
                               v-session-language
                               snapshot
                               nil
                               agent)]
           {:response (ok response-existing-user)
            :transaction update-code-tx})

         :else
         (let [code (utils/generate-phone-confirmation-code 4)
               create-user (db-user/creation-transaction
                            {:phone-number v-phone-number
                             :confirmation-code code})
               user (first create-user)
               hooks-transaction ((:create-account-with-phone-number-hooks-transaction config)
                                  user
                                  v-session-language
                                  agent) 
               token (utils/generate-token config user v-session-id)]
           {:response (ok {:success true
                           :internal-user-id (:app/uuid user)
                           :access-token token})
            :transaction (concat
                          create-user
                          hooks-transaction
                          (db-session/creation-transaction
                           {:sync-status :user-session.sync-status/needs-counter-zeroing
                            :session-id v-session-id
                            :session-language v-session-language
                            :user user}))})))
     (f/when-failed [e] (:message e)))))

(defn resend-confirmation-sms
  [config {:keys [phone-number session-language agent]}]
  (f/attempt-all
   [v-session-language (validators/language-code session-language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/phone-number phone-number)
         update-code ((:get-update-code-fn config) :create-account-with-phone-number)
         update-code-tx (update-code
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

       (empty? update-code-tx)
       {:response :auth-confirm/too-many-sms
        :transaction []}

       :else
       {:response (ok {:success true})
        :transaction update-code-tx}))
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
         {:response (ok {:success true})
          :transaction (concat
                        (db-user/update-email-transaction user v-email)
                        ((:add-email-hooks-transaction config)
                         snapshot
                         user
                         v-email))}))
     (f/when-failed [e]
                    (read-string (:message e))))))

(defn login-with-phone-number
  [config {:keys [phone-number password session-id session-language]}]
  (f/attempt-all
   [v-session-id (validators/string->uuid session-id "session-id")
    v-session-language (validators/language-code session-language)]
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
       {:response (ok (db-user/login-success-response config snapshot user v-session-id))
        :transaction (concat
                      (db-user/login-transaction user)
                      (session-transaction
                       {:snapshot snapshot
                        :config config
                        :session-id v-session-id
                        :user user
                        :session-language v-session-language}))}))
   (f/when-failed [e] (:message e))))