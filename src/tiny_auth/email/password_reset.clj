(ns tiny-auth.email.password-reset
  (:require [ring.util.http-response :refer [ok]]
            [clj-time.coerce :as c]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [clj-time.core :as time]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]
            [schema.core :as s]))

(s/defschema InitiatePasswordResetBody
  {:email s/Str
   (s/optional-key :path) s/Str
   :language s/Str})

(defn initiate-password-reset
  [config {:keys [email path language]}]
  (f/attempt-all
   [v-language (validators/language-code config language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/email email)]
   (cond
     (nil? user)
     {:response :auth-password-reset-initiate/bad-auth
      :transaction []}

     (not (:user/confirmed user))
     {:response :auth-password-reset-initiate/not-confirmed
      :transaction []}
     
     (not (:user/password-hash user))
     {:response :auth-password-reset-initiate/missing-password
      :transaction []}

     :else
     (let [password-token (utils/generate-password-token config user)
           hooks-result ((:password-reset-initiate-hooks config)
                         snapshot
                         user
                         password-token
                         path
                         v-language)]
       (if (:success hooks-result)
         {:response (ok {:success true})
          :transaction (concat
                        (db-user/update-last-reminder-transaction user)
                        (:transaction hooks-result))
          :hooks-transaction (:hooks-transaction hooks-result)}
         {:response :auth-password-reset-initiate/too-often
          :transaction []}))))
   (f/when-failed [e] (:message e))))

(s/defschema ConfirmPasswordResetBody
  {:password s/Str
   :language s/Str})

(defn confirm-password-reset
  [config {:keys [token password language]}]
  (f/attempt-all
   [_ (validators/password-strength password)
    v-language (validators/language-code config language)]
   (let [snapshot ((:db config) (:conn config))
         {exp :exp
          uuid :password-recovery-user
          password-hash :password-hash} (try (utils/unsign-token config token)
                                             (catch Exception _))
         ok? (time/before? (time/now) (c/from-long (* 1000 exp)))
         user (db-user/get-by-string-uuid config snapshot uuid)]
     (cond
       (nil? uuid)
       {:response :access-rules/missing-header
        :transaction []}

       (nil? (:user/email user))
       {:response :auth-password-reset-confirm/bad-auth
        :transaction []}

       (or (not ok?)
           (not= password-hash (utils/md5 (:user/password-hash user))))
       {:response :auth-password-reset-confirm/token-expired
        :transaction []}

       (and (:user/last-password-reset user)
            (not (utils/check-reset-frequency config (:user/last-password-reset user))))
       {:response :auth-password-reset-confirm/too-often
        :transaction []}

       :else
       (let [hooks-result ((:password-reset-confirm-hooks config)
                           user
                           password
                           v-language)
             reset-password (db-user/change-password-transaction
                             (:db/id user)
                             password)]
         {:response (ok {:success true
                         :email (:user/email user)})
          :transaction (concat
                        reset-password
                        (:transaction hooks-result)
                        (db-user/update-last-reset-transaction user))
          :hooks-transaction (:hooks-transaction hooks-result)})))
   (f/when-failed [e] (:message e))))

(defn change-password
  [config {:keys [user old-password new-password]}]
  (let [password-hash (or (:user/password-hash user) "")
        valid-old-password? (or (= password-hash "")
                                (utils/check-password old-password password-hash))]
    (cond
      (not (utils/check-login-frequency config user))
      {:response :auth-change-password/too-often
       :transaction []}

      (not valid-old-password?)
      {:response :auth-change-password/bad-auth
       :transaction (db-user/failed-login-transaction user)}

      :else
      (f/attempt-all
       [processed-password (validators/password-strength new-password)]
       {:response (ok {:success true})
        :transaction (db-user/change-password-transaction (:db/id user) processed-password)}
       (f/when-failed [e] (:message e))))))
