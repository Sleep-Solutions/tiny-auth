(ns tiny-auth.admin
  (:require [ring.util.http-response :refer [ok]]
            [tiny-auth.db.core :as db]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [tiny-auth.validators :as validators]))

(defn- user? [user-role]
  (= user-role :role/user))

(defn- admin? [user-role]
  (or (= user-role :role/superadmin)
      (= user-role :role/admin)))

(defn- superadmin? [user-role]
  (= user-role :role/superadmin))

(defn- activation-status [user]
  (if (not (:user/deactivated user)) "active" "deactive"))

(defn admin-endpoint [{:keys [success-response error-response]}]
  (fn [config {:keys [user-uuid admin-user] :as params}]
    (let [snapshot ((:db config) (:conn config))]
      (f/attempt-all
       [v-user (validators/user-from-string-uuid config user-uuid snapshot)]
       (let [user-role (->> v-user
                            :user/role
                            (db/solve-enum config snapshot))
             admin-user-role (->> admin-user
                                  :user/role
                                  (db/solve-enum config snapshot))]
         (cond
           (user? user-role)
           (success-response v-user params)

           (admin? user-role)
           (if (superadmin? admin-user-role)
             (success-response v-user params)
             error-response)

           :else
           error-response))
       (f/when-failed [e] (:message e))))))

(def activate-account
  (admin-endpoint
   {:success-response (fn [user _]
                        {:response (ok {:success true})
                         :transaction [[:db/add (:db/id user) :user/deactivated false]]})
    :error-response {:response :auth-admin-activate-account/access-denied
                     :transaction []}}))

(def deactivate-account
  (admin-endpoint
   {:success-response (fn [user _]
                        {:response (ok {:success true})
                         :transaction [[:db/add (:db/id user) :user/deactivated true]]})
    :error-response {:response :auth-admin-deactivate-account/access-denied
                     :transaction []}}))

(def check-activation-status
  (admin-endpoint
   {:success-response (fn [user _]
                        {:response (ok {:success true
                                        :activation-status (activation-status user)})
                         :transaction []})
    :error-response {:response :auth-admin-check-activation-status/access-denied
                     :transaction []}}))

(def change-password 
  (admin-endpoint 
   {:success-response (fn [user {:keys [new-password]}]
                        {:response (ok {:success true})
                         :transaction (db-user/change-password-transaction (:db/id user) new-password)})
    :error-response {:response :auth-admin-change-password/access-denied
                     :transaction []}}))
