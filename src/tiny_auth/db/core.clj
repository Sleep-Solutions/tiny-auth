(ns tiny-auth.db.core)

(defn uuid [] (java.util.UUID/randomUUID))

(defn create-entity-transaction
  "Creates a new entity transaction from a map or seq of maps"
  [m]
  (let [id (uuid)]
    (map #(merge % {:app/uuid id
                    :db/id (.toString id)})
         (cond (map? m) [m]
               (seq? m) m
               :else (assert false "Not a map nor a sequence passed as a transaction")))))

(defn solve-enum
  ([config snapshot enum]
   (if (keyword? enum)
     enum
     (->> enum
          :db/id
          ((:pull config) snapshot '[:db/ident])
          :db/ident))))