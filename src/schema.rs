table! {
    districts (id) {
        id -> Int8,
        slug -> Text,
        display_name -> Text,
        unvaccinated -> Int8,
        vaccinated -> Int8,
        interested -> Int8,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Int8,
        username -> Text,
        token -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

allow_tables_to_appear_in_same_query!(
    districts,
    users,
);
