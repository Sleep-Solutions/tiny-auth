(ns tiny-auth.third-party.utils
  (:require [tiny-auth.db.session :as db-session]))

(defn session-transaction
  [{:keys [snapshot config session-id user session-language]}]
  (if-let [existing-session (db-session/get-session config snapshot user session-id)]
    (db-session/update-language-transaction
     existing-session
     session-language)
    (db-session/creation-transaction
     {:sync-status :user-session.sync-status/needs-counter-zeroing
      :session-id session-id
      :session-language session-language
      :user user})))