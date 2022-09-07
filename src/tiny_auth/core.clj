(ns tiny-auth.core
  (:require [ring.util.http-response :refer [ok]]
            [tiny-auth.db.user :as db-user]
            [tiny-auth.db.session :as db-session]
            [tiny-auth.utils :as utils]
            [tiny-auth.validators :as validators]
            [failjure.core :as f]))

(defn renew-token [config {:keys [user session-id]}]
  {:response (ok {:success true
                  :access-token (utils/generate-token config user session-id)
                  :internal-user-id (:app/uuid user)})
   :transaction (db-user/login-transaction user)})

(defn change-language [config {:keys [session-language session-id user]}]
  (f/attempt-all
   [v-session-language (validators/language-code session-language)]
   (let [snapshot ((:db config) (:conn config))
         session (db-session/get-session config snapshot user session-id)]
     {:response (ok {:success true})
      :transaction (db-session/update-language-transaction
                    session
                    v-session-language)})
   (f/when-failed [e] (:message e))))