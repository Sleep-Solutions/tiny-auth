(ns tiny-auth.phone-number.password-reset
  (:require [ring.util.http-response :refer [ok]]
            [clj-time.coerce :as c]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [clj-time.core :as time]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn initiate-password-reset
  [config {:keys [phone-number language agent]}]
  (f/attempt-all
   [v-language (validators/language-code language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/phone-number phone-number)
         update-code ((:get-update-code-fn config) :initiate-password-reset)
         update-code-result (update-code
                             user
                             nil
                             v-language
                             snapshot
                             nil
                             agent)]
     (cond
       (nil? user)
       {:response :auth-phone-number/bad-auth
        :transaction []}

       (not (:user/confirmed user))
       {:response :auth-password-reset-initiate/not-confirmed
        :transaction []}

       (not (:user/password-hash user))
       {:response :auth-login-phone-number/password-doesnt-exist
        :transaction []}

       (not (:success update-code-result))
       {:response :auth-confirm/too-many-sms
        :transaction []}

       :else 
       {:response (ok {:success true})
        :transaction (:transaction update-code-result)
        :hooks-transaction (:hooks-transaction update-code-result)}))
   (f/when-failed [e] (:message e))))

(defn confirm-code
  [config {:keys [phone-number code]}]
  (let [snapshot ((:db config) (:conn config))
        user (db-user/get-by-id config snapshot :user/phone-number phone-number)
        reminder-date (:user/last-reminder user)
        password-code (:user/password-reset-code user)
        correct-code? (utils/correct-code? config phone-number code password-code)]
    (cond
      (nil? user)
      {:response :auth-phone-number/bad-auth
       :transaction []}

      (not (utils/check-password-reset-code-frequency config user))
      {:response :auth-confirm-code/too-many-failures
       :transaction []}

      (not (utils/check-password-reset-code-expiry config reminder-date))
      {:response :auth-confirm-code/code-expired
       :transaction []}

      (not correct-code?)
      {:response :auth-confirm-code/bad-code
       :transaction (db-user/failed-password-reset-code-transaction user)}

      :else 
      {:response (ok {:success true
                      :token (utils/generate-password-token config user)})
       :transaction (db-user/update-last-reminder-transaction user)})))

(defn confirm
  [config {:keys [token password session-id session-language]}]
  (f/attempt-all
   [_ (validators/password-strength password)
    v-session-id (validators/string->uuid session-id "session-id")
    v-session-language (validators/language-code session-language)]
   (let [{exp :exp
          uuid :password-recovery-user
          password-hash :password-hash} (utils/unsign-token config token)
         valid-token? (time/before? (time/now) (c/from-long (* 1000 exp)))
         snapshot ((:db config) (:conn config))
         user (db-user/get-by-string-uuid config snapshot uuid)]
     (cond
       (nil? (:app/uuid user))
       {:response :auth-phone-number/bad-auth
        :transaction []}

       (or (not valid-token?)
           (not= password-hash (utils/md5 (:user/password-hash user))))
       {:response :auth-password-reset-confirm/token-expired
        :transaction []}

       :else
       {:response (ok {:success true
                       :internal-user-id (:app/uuid user)
                       :access-token (utils/generate-token config user v-session-id)})
        :transaction (concat
                      (db-user/phone-password-reset-transaction user)
                      (db-user/change-password-transaction (:db/id user) password)
                      (db-session/creation-transaction
                       {:sync-status :user-session.sync-status/needs-counter-zeroing
                        :session-id v-session-id
                        :session-language v-session-language
                        :user user}))}))
   (f/when-failed [e] (:message e))))