(ns tiny-auth.phone-number.claim
  (:require [com.walmartlabs.cond-let :refer [cond-let]]
            [ring.util.http-response :refer [ok]]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn initiate-claim
  [config {:keys [phone-number session-id session-language agent]}]
  (f/attempt-all
   [v-phone-number (validators/phone phone-number)
    v-session-id (validators/string->uuid session-id "session-id")
    v-session-language (validators/language-code session-language)]
   (let [snapshot ((:db config) (:conn config))
         user-with-phone-number (db-user/get-by-id
                                 config
                                 snapshot
                                 :user/phone-number
                                 v-phone-number)
         claiming-user (db-user/get-claiming-user config snapshot v-phone-number)]
     (cond-let
      (nil? user-with-phone-number)
      {:response :auth-claim-phone-number/no-user
       :transaction []}

      (nil? claiming-user)
      (let [create-claiming-user (db-user/claiming-user-creation-transaction
                                  v-phone-number)
            claiming-user (first create-claiming-user)
            hooks-result ((:initiate-claim-hooks config)
                          claiming-user
                          v-session-language
                          agent)
            token (utils/generate-token config claiming-user v-session-id)]
        {:response (ok {:success true
                        :internal-user-id (:app/uuid claiming-user)
                        :access-token token})
         :transaction (concat
                       create-claiming-user
                       (:transaction hooks-result)
                       (db-session/creation-transaction
                        {:sync-status :user-session.sync-status/needs-counter-zeroing
                         :session-id v-session-id
                         :session-language v-session-language
                         :user claiming-user}))
         :hooks-transaction (:hooks-transaction hooks-result)})

      :let [update-code ((:get-update-code-fn config) :initiate-claim)
            update-code-result (update-code
                                claiming-user
                                v-session-id
                                v-session-language
                                snapshot
                                nil
                                agent)]

      (not (:success update-code-result))
      {:response :auth-confirm/too-many-sms
       :transaction []}

      :else
      {:response (ok {:success true
                      :internal-user-id (:app/uuid claiming-user)
                      :access-token (utils/generate-token
                                     config
                                     claiming-user
                                     v-session-id)})
       :transaction (:transaction update-code-result)
       :hooks-transaction (:hooks-transaction update-code-result)}))
   (f/when-failed [e] (:message e))))

(defn initiate-change
  [config {:keys [user phone-number session-id agent]}]
  (let [snapshot ((:db config) (:conn config))
        session-language (db-session/get-session-language config snapshot session-id)]
    (f/attempt-all
     [v-phone-number (validators/phone phone-number)]
     (let [user-with-phone-number (db-user/get-by-id
                                   config
                                   snapshot
                                   :user/phone-number
                                   v-phone-number)]
       (cond-let
        (nil? user-with-phone-number)
        {:response :auth-claim-phone-number/no-user
         :transaction []}

        (= v-phone-number (:user/phone-number user))
        {:response :auth-claim-phone-number/phone-number
         :transaction []}

        :let [update-code ((:get-update-code-fn config) :initiate-claim)
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
         :hooks-transaction (:hooks-transaction update-code-result)})))))

(defn confirm-code
  [config {:keys [code internal-user-id]}]
  (let [snapshot ((:db config) (:conn config))
        claiming-user (db-user/get-by-string-uuid config snapshot internal-user-id)
        last-claim-date (:user/last-phone-number-claim claiming-user)
        claim-code (:user/phone-number-claim-code claiming-user)
        new-phone-number (:user/new-phone-number claiming-user)
        correct-code? (utils/correct-code? config new-phone-number code claim-code)
        user-with-phone-number (when new-phone-number
                                 (db-user/get-by-id
                                  config
                                  snapshot
                                  :user/phone-number
                                  new-phone-number))]
    (cond
      (nil? (:app/uuid claiming-user))
      {:response :auth-phone-number/bad-auth
       :transaction []}

      (not (utils/check-phone-number-claim-code-frequency config claiming-user))
      {:response :auth-confirm-code/too-many-failures
       :transaction []}

      (nil? new-phone-number)
      {:response :auth-confirm-code/code-expired
       :transaction []}

      (not (utils/check-phone-number-claim-code-expiry config last-claim-date))
      {:response :auth-confirm-code/code-expired
       :transaction []}

      (not correct-code?)
      {:response :auth-confirm-code/bad-code
       :transaction (db-user/failed-phone-number-claim-code-transaction claiming-user)} 

      :else
      (let [token (utils/generate-reset-phone-number-token
                   config
                   user-with-phone-number)
            hooks-result ((:claim-confirm-code-hooks config)
                          snapshot
                          user-with-phone-number
                          claiming-user
                          token)]
        {:response (ok {:success true
                        :token ""})
         :transaction (concat
                       (db-user/claim-phone-number-transaction
                        claiming-user
                        user-with-phone-number)
                       (:transaction hooks-result))
         :hooks-transaction (:hooks-transaction hooks-result)}))))