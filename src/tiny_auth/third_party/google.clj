(ns tiny-auth.third-party.google
  (:require [com.walmartlabs.cond-let :refer [cond-let]]
            [ring.util.http-response :refer [ok]]
            [clojure.data.json :refer [read-str]]
            [tiny-auth.third-party.utils :refer [session-transaction]]
            [clj-http.client :as client]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f] 
            [tiny-auth.validators :as validators]))

(defn login-with-google
  [config {:keys [google-token google-user session-id session-language]}]
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
         google-response
         (client/get
          (str "https://oauth2.googleapis.com/tokeninfo?id_token="
               google-token
               "&") {:as :json
                     :throw-exceptions false})]
     (cond-let

      (nil? google-response)
      {:response :auth-login-google/unable-to-connect
       :transaction []}

      :let [rsp (if (map? (:body google-response))
                  (:body google-response)
                  (read-str (:body google-response) :key-fn keyword))]

      (not= (int (/ (:status google-response) 100)) 2)
      {:response :auth-login-google/google-error
       :message [(-> rsp :error_description)]
       :transaction []}

      :let [google-pre-id (:sub rsp)
            google-id (str google-pre-id)
            verified? (:email_verified rsp)]

      (nil? google-pre-id)
      {:response :auth-login-google/standard-error
       :transaction []}

      (not= google-id google-user)
      {:response :auth-login-google/standard-error
       :transaction []}

      (not verified?)
      {:response :auth-login-google/not-verified
       :transaction []}

      :let [user (or
                  (db-user/get-by-id config snapshot :user/google-id google-id)
                  (db-user/get-by-id config snapshot :user/email (:email rsp)))]
      user
      {:response (ok (response-from-user user))
       :transaction (concat
                     (db-user/login-transaction user)
                     (db-user/confirm-transaction user)
                     (db-user/update-id-transaction user :user/google-id google-id)
                     (session-transaction
                      {:config config
                       :snapshot snapshot
                       :user user
                       :session-id v-session-id
                       :session-language v-session-language}))}

      :else
      (let [create-transaction (db-user/creation-transaction
                                {:username (if-let [email (:email rsp)] email google-id)
                                 :google-id google-id
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
