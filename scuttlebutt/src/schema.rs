// @generated automatically by Diesel CLI.

diesel::table! {
    channels (id) {
        id -> Int8,
        src_group -> Int8,
        name -> Text,
        members -> Array<Int8>,
        private -> Bool,
    }
}

diesel::table! {
    groups (id) {
        id -> Int8,
        name -> Text,
        members -> Array<Int8>,
        is_dm -> Bool,
        channels -> Array<Int8>,
        admin -> Array<Int8>,
        owner -> Int8,
    }
}

diesel::table! {
    messages (channel) {
        channel -> Int8,
        id -> Int8,
        author -> Int8,
        content -> Nullable<Text>,
        thread -> Nullable<Int8>,
    }
}

diesel::table! {
    user_dms (id) {
        id -> Int8,
        dms -> Array<Int8>,
    }
}

diesel::table! {
    user_groups (id) {
        id -> Int8,
        groups -> Array<Int8>,
    }
}

diesel::table! {
    users (id) {
        id -> Int8,
        name -> Text,
        email -> Text,
        hash -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    channels,
    groups,
    messages,
    user_dms,
    user_groups,
    users,
);
