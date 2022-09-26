(ns tiny-auth.phone-number.change
  (:require [com.walmartlabs.cond-let :refer [cond-let]]
            [ring.util.http-response :refer [ok]]
            [failjure.core :as f]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn initiate-change
  [config {:keys [phone-number user session-id agent]}] 
  (f/attempt-all
   [v-phone-number (validators/phone phone-number)]
   (let [snapshot ((:db config) (:conn config))
         session-language (db-session/get-session-language config snapshot session-id)
         user-with-phone-number (db-user/get-by-id
                                 config 
                                 snapshot 
                                 :user/phone-number 
                                 v-phone-number)]
     (cond-let
      (:app/uuid user-with-phone-number)
      {:response :validators/user-uniqueness
       :transaction []}

      :let [update-code ((:get-update-code-fn config) :initiate-change)
            update-code-result (update-code
                                user
                                nil
                                session-language
                                snapshot
                                (fn [user] (assoc user :user/new-phone-number v-phone-number))
                                agent)
            same-number? (= (:user/new-phone-number user) v-phone-number)]

      (not (:success update-code-result))
      {:response (if same-number?
                   :auth-confirm/too-many-sms
                   :auth-phone-number-change/too-frequent)
       :transaction []}

      :else
      {:response (ok {:success true})
       :transaction (concat
                     (:transaction update-code-result)
                     (db-user/update-new-phone-number user v-phone-number))
       :hooks-transaction (:hooks-transaction update-code-result)}))))

(defn confirm-code
  [config {:keys [user code]}]
  (let [snapshot ((:db config) (:conn config))
        last-phone-number-change-date (:user/last-phone-number-change user)
        change-phone-number-code (:user/phone-number-change-code user)
        new-phone-number (:user/new-phone-number user)
        correct-code? (utils/correct-code?
                       config
                       new-phone-number
                       code
                       change-phone-number-code)
        user-with-phone-number (when new-phone-number
                                 (db-user/get-by-id
                                  config
                                  snapshot
                                  :user/phone-number
                                  new-phone-number))]
    (cond
      (:app/uuid user-with-phone-number)
      {:response :validators/user-uniqueness
       :transaction []}

      (not (utils/check-phone-number-change-code-frequency config user))
      {:response :auth-confirm-code/too-many-failures
       :transaction []}

      (not (utils/check-phone-number-change-code-expiry config last-phone-number-change-date))
      {:response :auth-confirm-code/code-expired
       :transaction []}

      (nil? new-phone-number)
      {:response :auth-confirm-code/code-expired
       :transaction []}

      (not correct-code?)
      {:response :auth-confirm-code/bad-code
       :transaction (db-user/failed-phone-number-change-code-transaction user)}

      :else
      (let [hooks-result ((:change-confirm-code-hooks config) snapshot user)]
       {:response (ok {:success true
                       :token ""})
        :transaction (concat
                      (db-user/change-phone-number-transaction user)
                      (:transaction hooks-result))
        :hooks-transaction (:hooks-transaction hooks-result)}))))