(ns tiny-auth.third-party.twitch
  (:require [com.walmartlabs.cond-let :refer [cond-let]]
            [ring.util.http-response :refer [ok]]
            [clojure.data.json :refer [read-str]]
            [clj-http.client :as client]
            [tiny-auth.db.user :as db-user]))

(defn add-twitch
  [config {:keys [user twitch-token twitch-user]}]
  (let [snapshot ((:db config) (:conn config))
        response-from-user (fn [user]
                             (db-user/login-success-response config snapshot user nil))
        response (client/get "https://api.twitch.tv/kraken/user"
                             {:headers {"Accept" "application/vnd.twitchtv.v5+json"
                                        "Authorization" (str "OAuth " twitch-token)}
                              :as :json
                              :throw-exceptions false})
        body (if (map? (:body response))
               (:body response)
               (read-str (:body response) :key-fn keyword))]
    (cond
      (not= (int (/ (:status response) 100)) 2)
      {:response :auth-add-twitch/twitch-error
       :message [(:message body)]
       :transaction []}

      (not= twitch-user (:_id body))
      {:response :auth-add-twitch/standard-error
       :transaction []}

      (not (and (:email_verified body) (:email body)))
      {:response :auth-add-twitch/email-unconfirmed
       :transaction []}

      (not (:user/twitch-id user))
      {:transaction (concat
                     (db-user/login-transaction user)
                     (db-user/update-id-transaction user :user/twitch-id twitch-user))
       :response (ok (response-from-user user))}

      :else
      {:response :auth-add-twitch/already-attached
       :transaction []})))

(defn login-with-twitch
  [config {:keys [twitch-token twitch-user]}]
  (let [snapshot ((:db config) (:conn config))
        response (client/get "https://api.twitch.tv/kraken/user"
                             {:headers {"Accept" "application/vnd.twitchtv.v5+json"
                                        "Authorization" (str "OAuth " twitch-token)}
                              :as :json
                              :throw-exceptions false})
        body (if (map? (:body response)) ; because in case of an error the json conversion is not automatically triggered
               (:body response)
               (read-str (:body response) :key-fn keyword))
        response-from-user (fn [user]
                             (db-user/login-success-response config snapshot user nil))]
    (cond-let
     (not= (int (/ (:status response) 100)) 2)
     {:response :auth-add-twitch/twitch-error
      :message [(:message body)]
      :transaction []}

     (not= twitch-user (:_id body))
     {:response :auth-add-twitch/standard-error
      :transaction []}

     (not (and (:email_verified body) (:email body)))
     {:response :auth-add-twitch/email-unconfirmed
      :transaction []}

     :let [user (or
                 (db-user/get-by-id config snapshot :user/twitch-id twitch-user)
                 (db-user/get-by-id config snapshot :user/email (:email body)))]
     user
     {:response (ok (response-from-user user))
      :transaction (concat
                    (db-user/login-transaction user)
                    (db-user/update-id-transaction user :user/twitch-id twitch-user))}

     :else
     (let [create-transaction (db-user/creation-transaction
                               {:username (:email body)
                                :email (:email body)
                                :twitch-id twitch-user
                                :confirmed true})
           user (first create-transaction)]
       {:response (ok (response-from-user user))
        :transaction (concat
                      create-transaction
                      (db-user/login-transaction user))}))))