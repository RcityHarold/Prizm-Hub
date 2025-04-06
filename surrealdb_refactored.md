
# Refactored SurrealDB Integration in Rust

This guide provides improved implementations for interacting with SurrealDB in Rust, featuring better response handling and reduced boilerplate.

---

## 📦 Step 1: Define Common Response Structure

```rust
#[derive(Debug, Deserialize)]
struct SurrealResponse<T> {
    status: String,
    time: String,
    result: Vec<T>,
}

fn extract_surreal_result<T: DeserializeOwned>(value: &serde_json::Value) -> Result<Vec<T>> {
    let parsed: Vec<SurrealResponse<T>> = serde_json::from_value(value.clone())
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse surreal response: {}", e)))?;
    if let Some(first) = parsed.first() {
        Ok(first.result.clone())
    } else {
        Ok(vec![])
    }
}
```

---

## 🔍 find_record_by_field

```rust
pub async fn find_record_by_field<T>(&self, table: &str, field: &str, value: &str) -> Result<Option<T>>
where
    T: DeserializeOwned + Clone,
{
    let sql = format!("SELECT * FROM {} WHERE {} = '{}'", table, field, value);
    let result = self.execute_sql(&sql).await?;
    let mut records: Vec<T> = extract_surreal_result(&result)?;
    Ok(records.pop())
}
```

---

## ➕ create_record

```rust
pub async fn create_record<T>(&self, table: &str, record: &T) -> Result<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    let content = serde_json::to_string(record)?;
    debug!("Creating record in table {}: {}", table, content);

    let create_sql = format!("INSERT INTO {} {} RETURN AFTER", table, content);
    let result = self.execute_sql(&create_sql).await?;

    let mut records: Vec<T> = extract_surreal_result(&result)?;
    records.pop().ok_or_else(|| AuthError::DatabaseError("Failed to create record".to_string()))
}
```

---

## 🔄 update_record

```rust
pub async fn update_record<T>(&self, table: &str, id: &str, record: &T) -> Result<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    let sql = format!(
        "UPDATE {} SET {} WHERE id = '{}'",
        table,
        serde_json::to_string(record)?,
        id
    );

    let result = self.execute_sql(&sql).await?;
    let mut records: Vec<T> = extract_surreal_result(&result)?;
    records.pop().ok_or_else(|| AuthError::DatabaseError("Failed to update record".to_string()))
}
```

---

## ❌ delete_record

```rust
pub async fn delete_record<T>(&self, table: &str, id: &str) -> Result<Option<T>>
where
    T: DeserializeOwned + Clone,
{
    let sql = format!("DELETE FROM {} WHERE id = '{}'", table, id);
    let result = self.execute_sql(&sql).await?;
    let mut records: Vec<T> = extract_surreal_result(&result)?;
    Ok(records.pop())
}
```

---

## ✅ Benefits

- Unified result parsing
- Cleaner and safer control flow
- Ready for future extension and error handling

---

