(ns tiny-auth.third-party.facebook
  (:require [com.walmartlabs.cond-let :refer [cond-let]]
            [ring.util.http-response :refer [ok]]
            [clojure.data.json :refer [read-str]]
            [tiny-auth.third-party.utils :refer [session-transaction]]
            [clj-http.client :as client]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f] 
            [tiny-auth.validators :as validators]))

(defn login-with-facebook 
  [config {:keys [facebook-user facebook-token session-id session-language]}]
  (f/attempt-all
   [v-session-id (validators/string->uuid session-id "session-id")
    v-session-language (validators/language-code config session-language)]
   (let [snapshot ((:db config) (:conn config))
         response-from-user (fn [user]
                              (db-user/login-success-response
                               config
                               snapshot
                               user
                               v-session-id))
         fb-response
         (client/get
          (str "https://graph.facebook.com/me?fields=id,email,first_name,last_name&access_token="
               facebook-token
               "&")
          {:as :json
           :throw-exceptions false})]
     (cond-let

      (nil? fb-response)
      {:response :auth-login-fb/unable-to-connect
       :transaction []}

      :let [rsp (if (map? (:body fb-response))
                  (:body fb-response)
                  (read-str (:body fb-response) :key-fn keyword))
            facebook-id (:id rsp)]

      (not= (int (/ (:status fb-response) 100)) 2)
      {:response :auth-login-fb/facebook-error
       :message [(-> rsp :error :message)]
       :transaction []}

      (nil? facebook-id)
      {:response :auth-login-fb/standard-error
       :transaction []}

      (not= facebook-id facebook-user)
      {:response :auth-login-fb/standard-error
       :transaction []}

      :let [user (db-user/get-by-id config snapshot :user/facebook-id facebook-id)]
      user
      {:response (ok (response-from-user user))
       :transaction (concat
                     (db-user/login-transaction user)
                     (db-user/confirm-transaction user))}

      :let [user (db-user/get-by-id config snapshot :user/email (:email rsp))]
      user 
      {:response (ok (response-from-user user))
       :transaction (concat
                     (db-user/login-transaction user)
                     (db-user/update-id-transaction user :user/facebook-id facebook-id)
                     (session-transaction
                      {:config config
                       :snapshot snapshot
                       :user user
                       :session-id v-session-id
                       :session-language v-session-language}))}

      :else
      (let [create-transaction (db-user/creation-transaction
                                {:username (if-let [email (:email rsp)] email facebook-id)
                                 :facebook-id facebook-id
                                 :email (:email rsp)
                                 :confirmed true})
            user (first create-transaction)
            session-transaction (db-session/creation-transaction
                                 {:sync-status :user-session.sync-status/needs-counter-zeroing
                                  :session-id v-session-id
                                  :session-language v-session-language
                                  :user user})]
        {:response (ok (response-from-user user))
         :transaction (concat
                       create-transaction
                       (db-user/login-transaction user)
                       session-transaction)})))
   (f/when-failed [e] (:message e))))
