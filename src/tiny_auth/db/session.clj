(ns tiny-auth.db.session
  (:require [tiny-auth.db.core :as db]))

(def user-session-schema 
  [{:db/ident              :user-session.sync-status/needs-counter-zeroing}
   {:db/ident              :user-session.sync-status/ok}

   {:db/ident              :user-session/sync-status
    :db/valueType          :db.type/ref
    :db/cardinality        :db.cardinality/one
    :db/doc                "The synchronisation status of the session"}

   {:db/ident              :user-session/session-id
    :db/valueType          :db.type/uuid
    :db/cardinality        :db.cardinality/one
    :db/doc                "Session id"}

   {:db/ident              :user-session/session-language
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "Session language"}])

(defn create-schema [config] 
  @((:transact config) (:conn config) user-session-schema))

(defn creation-transaction
  [{:keys
    [sync-status
     session-id
     session-language
     user]}]
  (assert (keyword? sync-status))
  (assert (uuid? session-id))
  (assert (:db/id user))
  (let [creation-transaction (db/create-entity-transaction
                              {:user-session/sync-status sync-status
                               :user-session/session-id session-id
                               :user-session/session-language session-language
                               :app/updatedAt (java.util.Date.)})
        session (first creation-transaction)]
    (concat creation-transaction 
            [[:db/add (:db/id user) :user/sessions (:db/id session)]])))

(defn get-session [config snapshot user session-id]
  (assert (uuid? session-id))
  (assert (:db/id user))
  (ffirst
   ((:q config)
    '[:find (pull ?s [*])
      :in $ ?session-id ?user
      :where
      [?user :user/sessions ?s]
      [?s :user-session/session-id ?session-id]]
    snapshot session-id (:db/id user))))

(defn get-session-language [config snapshot session-id]
  (assert (uuid? session-id))
  (let [session-language (ffirst
                          ((:q config)
                           '[:find ?language
                             :in $ ?session
                             :where
                             [?s :user-session/session-id ?session]
                             [?s :user-session/session-language ?language]]
                           snapshot session-id))]
    (or session-language "English")))

(defn update-language-transaction [session language]
  (assert (string? language))
  (assert (:db/id session))
  [[:db/add (:db/id session) :user-session/session-language language]
   [:db/add (:db/id session) :app/updatedAt (java.util.Date.)]])