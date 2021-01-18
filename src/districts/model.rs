use crate::db;
use crate::error_handler::CustomError;
use crate::schema::districts;
use chrono::{NaiveDateTime, Utc};
use diesel::{prelude::*, sql_types::{BigInt}};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Identifiable, Queryable, AsChangeset, Insertable)]
#[table_name = "districts"]
pub struct District {
    pub id: i64,
    pub slug: String,
    pub display_name: String,
    pub unvaccinated: i64,
    pub vaccinated: i64,
    pub interested: i64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Deserialize, AsChangeset, Insertable)]
#[table_name = "districts"]
pub struct InsertableDistrict {
    pub slug: String,
    pub display_name: String,
}

#[derive(Debug, Queryable, QueryableByName, Serialize, Deserialize)]
struct Summary {
    #[sql_type = "BigInt"]
    pub vaccinated: i64,
    #[sql_type = "BigInt"]
    pub unvaccinated: i64,
    #[sql_type = "BigInt"]
    pub interested: i64,
}

impl District {
    pub fn increment(id: i64, unvaccinated: bool, vaccinated: bool, interested: bool) -> Result<Self, CustomError> {
        let conn = db::connection()?;
        let query = diesel::update(districts::table)
            .filter(districts::id.eq(id));

        match (vaccinated, unvaccinated, interested) {
            (false, false, false) => {
                return Ok(districts::table.filter(districts::id.eq(id)).first(&conn)?);
            },
            (false, false, true) => {
                return Ok(query.set((
                    districts::interested.eq(districts::interested + 1),
                )).get_result(&conn)?);
            },
            (false, true, false) => {
                log::info!("Incrementing unvaccinated ...");
                return Ok(query.set((
                    districts::unvaccinated.eq(districts::unvaccinated + 1),
                )).get_result(&conn)?);
            },
            (false, true, true) => {
                return Ok(query.set((
                    districts::unvaccinated.eq(districts::unvaccinated + 1),
                    districts::interested.eq(districts::interested + 1),
                )).get_result(&conn)?);
            },
            (true, false, true) => {
                return Ok(query.set((
                    districts::vaccinated.eq(districts::vaccinated + 1),
                    districts::interested.eq(districts::interested + 1),
                )).get_result(&conn)?);
            },
            (true, false, false) => {
                log::info!("Incrementing vaccinated ...");
                return Ok(query.set((
                    districts::vaccinated.eq(districts::vaccinated + 1),
                )).get_result(&conn)?);
            },
            (true, true, false) => {
                return Ok(query.set((
                    districts::vaccinated.eq(districts::vaccinated + 1),
                    districts::unvaccinated.eq(districts::unvaccinated + 1),
                )).get_result(&conn)?);
            },
            (true, true, true) => {
                return Ok(query.set((
                    districts::vaccinated.eq(districts::vaccinated + 1),
                    districts::unvaccinated.eq(districts::unvaccinated + 1),
                    districts::interested.eq(districts::interested + 1),
                )).get_result(&conn)?);
            },
        };
    }

    pub fn find_by_id(id: i64) -> Result<Self, CustomError> {
        let conn = db::connection()?;
        let district = districts::table.filter(districts::id.eq(id))
            .get_result(&conn)?;
        Ok(district)
    }

    pub fn find_by_slug(slug: String) -> Result<Self, CustomError> {
        let conn = db::connection()?;
        let district = districts::table.filter(districts::slug.eq(slug))
            .get_result(&conn)?;
        Ok(district)
    }

    pub fn find(sorted: bool) -> Result<Vec<Self>, CustomError> {
        let conn = db::connection()?;
        let districts = match sorted {
            true => {
                log::trace!("Loading sorted districts ...");
                districts::table.order_by(districts::display_name.asc())
                    .load(&conn)?
            },
            false => {
                log::trace!("Loading unsorted districts ...");
                districts::table.load(&conn)?
            },
        };
        Ok(districts)
    }

    pub fn get_summary() -> Result<Self, CustomError> {
        let conn = db::connection()?;
        log::trace!("Beginning summary");
        let result = diesel::sql_query("SELECT 
            sum(vaccinated)::bigint as vaccinated,
            sum(unvaccinated)::bigint as unvaccinated,
            sum(interested)::bigint as interested
            FROM districts")
            .load::<Summary>(&conn)?;
       
        let district = District {
            id: 0,
            slug: String::from("summary"),
            display_name: String::from("Summary"),
            vaccinated: result[0].vaccinated,
            unvaccinated: result[0].unvaccinated,
            interested: result[0].interested,
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        };
        log::trace!("Found summary: {:?}", &district);
 
        Ok(district) 
    }

    pub fn update(id: i64, district: InsertableDistrict) -> Result<Self, CustomError> {
        let conn = db::connection()?;
        let district = diesel::update(districts::table)
            .filter(districts::id.eq(id))
            .set(district)
            .get_result(&conn)?;
        Ok(district)
    }

    pub fn create(district: InsertableDistrict) -> Result<Self, CustomError> {
        let conn = db::connection()?;
        let district = diesel::insert_into(districts::table)
            .values(district)
            .get_result(&conn)?;
        Ok(district)
    }

    pub fn delete(id: i64) -> Result<Self, CustomError> {
        let conn = db::connection()?;
        let res = diesel::delete(districts::table.filter(districts::id.eq(id)))
            .get_result(&conn)?;
        Ok(res)
    }
}
