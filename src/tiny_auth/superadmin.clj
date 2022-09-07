(ns tiny-auth.superadmin
  (:require [ring.util.http-response :refer [ok]]
            [tiny-auth.db.core :as db]
            [failjure.core :as f]
            [tiny-auth.validators :as validators]))

(defn change-role
  [config {:keys [user-uuid new-role]}]
  (let [snapshot ((:db config) (:conn config))]
   (f/attempt-all
    [v-user (validators/user-from-string-uuid config user-uuid snapshot)
     v-role (validators/role new-role)]
    {:response (ok {:success true})
     :transaction [[:db/add (:db/id v-user) :user/role v-role]]}
    (f/when-failed [e] (:message e)))))

(defn check-role 
  [config {:keys [user-uuid]}]
  (let [snapshot ((:db config) (:conn config))]
   (f/attempt-all
    [v-user (validators/user-from-string-uuid config user-uuid snapshot)]
    {:response (ok {:success true
                    :role (db/solve-enum config snapshot (:user/role v-user))})
     :transaction []}
    (f/when-failed [e] (:message e)))))