(ns tiny-auth.email.confirm
  (:require [ring.util.http-response :refer [ok]]
            [clj-time.coerce :as c]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [clj-time.core :as time] 
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn confirm-with-token
  [config {:keys [token]}]
  (try
    (let [snapshot ((:db config) (:conn config))
          {exp :exp
           uuid :user-confirmed} (utils/unsign-token config token)
          ok? (time/before? (time/now) (c/from-long (* 1000 exp))) 
          user (db-user/get-by-string-uuid config snapshot uuid)
          user-base-path (or (db-user/get-user-base-path user)
                             (:redirect-link config))]
      (cond
        (or (not ok?) (nil? (:user/email user)))
        {:response :auth-confirm-token/error-code-bad-token
         :user-base-path user-base-path
         :transaction []}

        (:user/confirmed user)
        {:response :auth-confirm-token/error-code-already-confirmed
         :user-base-path user-base-path
         :transaction []}

        :else
        {:response (ok {:success true})
         :user-base-path user-base-path
         :transaction [[:db/add (:db/id user) :user/confirmed true]]}))
    (catch Throwable e
      {:response :auth-confirm-token/token-exception
       :exception e
       :transaction []})))

(defn confirm-signup-with-token
  [config {:keys [token path language]}]
  (f/attempt-all
   [language-code (validators/language-code language)]
   (try
     (let [snapshot ((:db config) (:conn config))
           {exp :exp
            uuid :user-confirmed} (utils/unsign-token config token)
           ok? (time/before? (time/now) (c/from-long (* 1000 exp))) 
           user (db-user/get-by-string-uuid config snapshot uuid)
           user-base-path (if (seq path)
                            path
                            (or (db-user/get-user-base-path user)
                                (:redirect-link config)))]
       (cond
         (or (not ok?) (nil? user))
         {:response :auth-confirm-token/error-code-bad-token
          :user-base-path user-base-path
          :language-code language-code
          :transaction []}

         (:user/confirmed user)
         {:response :auth-confirm-token/error-code-already-confirmed
          :user-base-path user-base-path
          :language-code language-code
          :transaction []}

         :else
         {:response (ok {:success true})
          :language-code language-code
          :user-base-path user-base-path
          :transaction [[:db/add (:db/id user) :user/confirmed true]]}))
     (catch Throwable _
       {:response :auth-confirm-token/error-code-bad-token
        :language-code language-code
        :transaction []}))
   (f/when-failed [e] (:message e))))

(defn confirm-with-code
  [config {:keys [code internal-user-id]}]
  (try
    (let [snapshot ((:db config) (:conn config))
          user (db-user/get-by-string-uuid config snapshot internal-user-id) 
          confirmation-date (:user/last-confirmation user)
          db-code (:user/confirmation-code user)
          ok? (and user
                   db-code
                   (or (nil? confirmation-date)
                       (time/before? (time/now)
                                     (time/plus (utils/from-database-date confirmation-date)
                                                (time/seconds (eval (:confirmation-token-expiry config)))))))]
      (cond
        (not (utils/check-confirmation-code-frequency config user))
        {:response :auth-confirm-code/too-many-failures
         :transaction []}

        (not ok?)
        {:response :auth-confirm-code/code-expired
         :transaction []}

        (:user/confirmed user)
        {:response :auth-confirm-code/already-confirmed
         :transaction []}

        (utils/correct-code? config (:user/phone-number user) code db-code)
        {:response (ok {:success true})
         :transaction [[:db/add (:db/id user) :user/confirmed true]
                       [:db/add (:db/id user) :user/failed-confirmations-count 0]]}

        :else
        {:response :auth-confirm-code/bad-code
         :transaction []}))
    (catch Throwable _
      {:response :auth-confirm-code/bad-code
       :transaction []})))

(defn confirm
  [config {:keys [email path language]}]
  (f/attempt-all
   [v-language (validators/language-code language)]
   (let [snapshot ((:db config) (:conn config))
         user (db-user/get-by-id config snapshot :user/email email)]
     (cond
       (nil? user)
       {:response :auth-confirm/bad-auth
        :transaction []}

       (:user/confirmed user)
       {:response :auth-confirm/already-confirmed
        :transaction []}

       :else
       (let [code (utils/generate-confirmation-code)
             {:keys [success transaction]} ((:confirm-hooks config) 
                                            snapshot
                                            user
                                            path
                                            code
                                            v-language)]
         (if (not success)
           {:response :auth-confirm/too-many
            :transaction []}
           {:response (ok {:success true})
            :transaction (concat
                          transaction
                          [[:db/add (:db/id user) :user/confirmation-code code]]
                          (db-user/update-last-confirmed-transaction user))}))))
   (f/when-failed [e] (:message e))))