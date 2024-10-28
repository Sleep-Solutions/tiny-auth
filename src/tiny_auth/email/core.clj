(ns tiny-auth.email.core
  (:require [ring.util.http-response :refer [ok]]
            [clojure.data.json :refer [read-str]]
            [tiny-auth.db.user :as db-user]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]
            [failjure.core :as f]
            [schema.core :as s]))

(s/defschema SignUpBody
  {:email s/Str
   :password s/Str
   :session-id s/Str
   :session-language s/Str
   :additional-data s/Str
   (s/optional-key :path) s/Str})

(defn signup-with-email
  [config {:keys [email password session-id session-language additional-data path]}]
  (let [snapshot ((:db config) (:conn config))]
    (f/attempt-all
     [validated-email (validators/email config email)
      _ (validators/user-uniqueness-email config email snapshot)
      validated-password (validators/password-strength password)
      v-session-id (validators/string->uuid session-id "session-id")
      v-session-language (validators/language-code config session-language)
      _ (validators/string-size additional-data 1024 "additional-data")
      v-additional-data (validators/json-string additional-data)]
     (let [;; TODO: improve this, it can be dangerous.
           confirmed? (-> v-additional-data
                          (read-str :key-fn keyword)
                          :confirmed)
           create-user (db-user/creation-transaction
                        {:email validated-email
                         :password validated-password
                         :additional-data v-additional-data
                         :confirmed confirmed?
                         :confirmation-code (utils/generate-confirmation-code)})
           user (first create-user)
           hooks-result ((:signup-hooks config)
                         (assoc user :path path)
                         v-session-language)
           create-session (db-session/creation-transaction
                           {:sync-status :user-session.sync-status/needs-counter-zeroing
                            :session-id v-session-id
                            :session-language v-session-language
                            :user user})
           access-token (utils/generate-token config user v-session-id)]
       {:response (ok {:success true
                       :internal-user-id (:app/uuid user)
                       :access-token access-token})
        :transaction (concat
                      (:transaction hooks-result)
                      create-user
                      create-session)
        :hooks-transaction (:hooks-transaction hooks-result)})
     (f/when-failed [e] (:message e)))))

(s/defschema LogInBody
  {:email s/Str
   :password s/Str
   :session-id s/Str
   :session-language s/Str})

(defn login-with-email
  [config {:keys [email password session-id session-language]}]
  (f/attempt-all
   [v-session-id (validators/string->uuid session-id "session-id")
    v-session-language (validators/language-code config session-language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/email email)]
     (cond
       (nil? user)
       {:response :auth-login-email/bad-auth
        :transaction []}

       (not (utils/check-login-frequency config user))
       {:response :auth-login-email/too-many-failures
        :transaction []}

       (not (and
             (:user/password-hash user)
             (utils/check-password password (:user/password-hash user))))
       {:response :auth-login-email/bad-auth
        :transaction (db-user/failed-login-transaction user)}

       (:user/deactivated user)
       {:response :auth-login-email/deactivated-user
        :data {"internal-user-id" (:app/uuid user)}
        :transaction []}

       (nil? (:user/username user))
       {:response :auth-login-email/claimed-user
        :transaction []}

       (or (:dont-check-if-confirmed-in-login config) (:user/confirmed user))
       (let [existing-session (db-session/get-session
                               config
                               snapshot
                               user
                               v-session-id)
             session-transaction (if-not existing-session
                                   (db-session/creation-transaction
                                    {:sync-status :user-session.sync-status/needs-counter-zeroing
                                     :session-id v-session-id
                                     :session-language v-session-language
                                     :user user})
                                   (db-session/update-language-transaction
                                    existing-session
                                    v-session-language))
             final-transaction (concat session-transaction
                                       (db-user/login-transaction user))
             custom-log-in-data (when-let [get-custom-log-in-data (:get-custom-log-in-data config)]
                                  (get-custom-log-in-data snapshot user))
             log-in-response (db-user/login-success-response
                              config
                              snapshot
                              user
                              v-session-id)]
         {:response (ok (merge log-in-response custom-log-in-data))
          :transaction final-transaction})

       :else
       {:response :auth-login-email/not-confirmed
        :data {"internal-user-id" (:app/uuid user)}
        :transaction []}))
   (f/when-failed [e] (:message e))))

(defn check-email [config {:keys [email]}]
  (let [snapshot ((:db config) (:conn config))]
    (f/attempt-all
     [_ (validators/user-uniqueness-email config email snapshot)
      v-email (validators/email config email)]
     {:response (ok {:success true
                     :email v-email})
      :transaction []}
     (f/when-failed [e] (:message e)))))
