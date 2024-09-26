(ns tiny-auth.third-party.apple
  (:require [com.walmartlabs.cond-let :refer [cond-let]]
            [ring.util.http-response :refer [ok]]
            [tiny-auth.third-party.utils :refer [session-transaction]]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]))

(defn login-with-apple
  [config {:keys [jwt-token session-id session-language]}]
  (let [snapshot ((:db config) (:conn config))
        response-from-user (fn [user session-id]
                            (db-user/login-success-response
                             config
                             snapshot
                             user
                             session-id))
        {header :header payload :payload} (utils/decode jwt-token)
        payload (utils/fmap-keys keyword payload)
        apple-id (:sub payload)
        email (:email payload)]
    (f/attempt-all
     [v-session-id (validators/string->uuid session-id "session-id")
      v-session-language (validators/language-code config session-language)
      v-payload (utils/validate-token config jwt-token header)
      _ (validators/exp (:exp v-payload))
      _ (validators/iss (:iss v-payload))
      _ (validators/aud config (:aud v-payload))]
     (cond-let
      :let [user (db-user/get-by-id config snapshot :user/apple-id apple-id)]
      user
      {:response (ok (db-user/login-success-response
                      config
                      snapshot
                      user
                      session-id))
       :transaction (concat
                     (db-user/login-transaction user)
                     (db-user/confirm-transaction user)
                     (session-transaction
                      {:config config
                       :snapshot snapshot
                       :user user
                       :session-id v-session-id
                       :session-language v-session-language}))}

      (nil? email)
      {:response :auth-login-apple/bad-token
       :transaction []}

      :let [user (db-user/get-by-id config snapshot :user/email email)]
      user
      {:response (ok (response-from-user user v-session-id))
       :transaction (concat
                     (db-user/login-transaction user)
                     (db-user/confirm-transaction user) 
                     (db-user/update-id-transaction user :user/apple-id apple-id)
                     (session-transaction
                      {:config config
                       :snapshot snapshot
                       :user user
                       :session-id v-session-id
                       :session-language v-session-language}))}

      :else
      (let [create-transaction (db-user/creation-transaction
                                {:username email
                                 :apple-id apple-id
                                 :email email
                                 :confirmed true})
            user (first create-transaction)
            session-transaction (db-session/creation-transaction
                                 {:sync-status :user-session.sync-status/needs-counter-zeroing
                                  :session-id (utils/string->uuid session-id)
                                  :user user})]
        {:response (ok (response-from-user user v-session-id))
         :transaction (concat
                       create-transaction
                       (db-user/login-transaction user)
                       session-transaction)})) 
     (f/when-failed [e] (:message e)))))
