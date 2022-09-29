(ns tiny-auth.phone-number.reset
  (:require [com.walmartlabs.cond-let :refer [cond-let]]
            [ring.util.http-response :refer [ok]]
            [clj-time.coerce :as c]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [clj-time.core :as time]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn initiate-reset
  [config {:keys [email path language]}]
  (f/attempt-all
   [v-language (validators/language-code language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/email email)
         last-reset-email (:user/last-phone-number-reset-email user)]
     (cond
       (not ((:check-user-role config) snapshot user))
       {:response :auth-reset-phone-number/bad-role
        :transaction []}

       (nil? user)
       {:response :auth-password-reset-initiate/bad-auth
        :transaction []}

       (not (:user/confirmed user))
       {:response :auth-password-reset-initiate/not-confirmed
        :transaction []}

       (not (:user/password-hash user))
       {:response :auth-login-phone-number/password-doesnt-exist
        :transaction []}

       (and last-reset-email
            (not (utils/check-phone-number-reset-email-frequency config last-reset-email)))
       {:response :auth-confirm/too-many
        :transaction []}

       :else
       (let [token (utils/generate-reset-phone-number-token config user)
             hooks-result ((:initiate-reset-hooks config)
                           user
                           token
                           path
                           v-language)]
         {:response (ok {:success true})
          :transaction (concat
                        (db-user/update-last-phone-number-reset-email-transaction user)
                        (:transaction hooks-result))
          :hooks-transaction (:hooks-transaction hooks-result)})))
   (f/when-failed [e] (:message e))))

(defn proceed-reset
  [config {:keys [token phone-number language agent]}]
  (f/attempt-all
   [v-language (validators/language-code language)
    v-phone-number (validators/phone phone-number)]
   (let [{exp :exp
          uuid :phone-number-reset-user} (utils/unsign-token config token)
         valid-token? (time/before? (time/now) (c/from-long (* 1000 exp)))
         snapshot ((:db config) (:conn config))
         user (db-user/get-by-string-uuid config snapshot uuid)
         user-with-phone-number (db-user/get-by-id config snapshot :user/phone-number phone-number)]
     (cond-let
      (:app/uuid user-with-phone-number)
      {:response :validators/user-uniqueness
       :transaction []}

      (nil? (:app/uuid user))
      {:response :auth-phone-number/bad-auth
       :transaction []}

      (not valid-token?)
      {:response :auth-phone-number-change-confirm/token-expired
       :transaction []}

      :let [update-code ((:get-update-code-fn config) :proceed-reset)
            update-code-result (update-code
                                user
                                nil
                                v-language
                                snapshot
                                (fn [user] (assoc user :user/new-phone-number v-phone-number))
                                agent)]

      (not (:success update-code-result))
      {:response :auth-confirm/too-many-sms
       :transaction []}

      :else
      {:response (ok {:success true})
       :transaction (concat
                     (:transaction update-code-result)
                     (db-user/update-new-phone-number user v-phone-number))
       :hooks-transaction (:hooks-transaction update-code-result)}))
   (f/when-failed [e] (:message e))))

(defn confirm-code 
  [config {:keys [token code session-id session-language]}]
  (f/attempt-all
   [v-session-id (validators/string->uuid session-id "session-id")
    v-session-language (validators/language-code session-language)]
   (let [snapshot ((:db config) (:conn config))
         user-uuid (->> token (utils/unsign-token config) :phone-number-reset-user)
         user (db-user/get-by-string-uuid config snapshot user-uuid)
         last-phone-number-reset-date (:user/last-phone-number-reset user)
         reset-phone-number-code (:user/phone-number-reset-code user)
         correct-code? (utils/correct-code?
                        config
                        (:user/new-phone-number user)
                        code
                        reset-phone-number-code)]
     (cond

       (not (utils/check-phone-number-reset-code-frequency config user))
       {:response :auth-confirm-code/too-many-failures
        :transaction []}

       (not (utils/check-phone-number-reset-code-expiry config last-phone-number-reset-date))
       {:response :auth-confirm-code/code-expired
        :transaction []}

       (not correct-code?)
       {:response :auth-confirm-code/bad-code
        :transaction (db-user/failed-phone-number-reset-code-transaction user)}

       :else
       (let [hooks-result ((:reset-confirm-code-hooks config) snapshot user)]
         {:response (ok {:success true
                         :internal-user-id (:app/uuid user)
                         :token (utils/generate-token config user v-session-id)})
          :transaction (concat
                        (db-user/update-reseting-user-transaction user)
                        (:transaction hooks-result)
                        (db-session/creation-transaction
                         {:sync-status :user-session.sync-status/needs-counter-zeroing
                          :session-id v-session-id
                          :session-language v-session-language
                          :user user}))
          :hooks-transaction (:hooks-transaction hooks-result)})))))