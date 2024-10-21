use async_graphql::{Context, Object};
use ::chrono::Local;
use chrono::{NaiveDate, NaiveTime, Duration};
use chrono_tz::Asia::Kolkata;
use sqlx::PgPool;
use std::sync::Arc;
use hmac::{Hmac,Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use crate::db::{member::Member, attendance::Attendance};

pub struct MutationRoot;

#[Object]
impl MutationRoot {

    //Mutation for adding members to the Member table
    async fn add_member(
        &self, 
        ctx: &Context<'_>, 
        rollno: String, 
        name: String, 
        hostel: String, 
        email: String, 
        sex: String, 
        year: i32,
        macaddress: String,

    ) -> Result<Member, sqlx::Error> {
        let pool = ctx.data::<Arc<PgPool>>().expect("Pool not found in context");



        let member = sqlx::query_as::<_, Member>(
            "INSERT INTO Member (rollno, name, hostel, email, sex, year, macaddress) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *"
        )
        .bind(rollno)
        .bind(name)
        .bind(hostel)
        .bind(email)
        .bind(sex)
        .bind(year)
        .bind(macaddress)
        .fetch_one(pool.as_ref())
        .await?;

        Ok(member)
    }

    
    //Mutation for adding attendance to the Attendance table
    async fn add_attendance(
       
        &self,
        
        ctx: &Context<'_>,
        id: i32,
        date: NaiveDate,
        timein: NaiveTime,
        timeout: NaiveTime,
        is_present: bool,
      
    ) -> Result<Attendance, sqlx::Error> {
        let pool = ctx.data::<Arc<PgPool>>().expect("Pool not found in context");


        let attendance = sqlx::query_as::<_, Attendance>(
            "INSERT INTO Attendance (id, date, timein, timeout, is_present) VALUES ($1, $2, $3, $4, $5) RETURNING *"
        )
        
        .bind(id)
        .bind(date)
        .bind(timein)
        .bind(timeout)
        .bind(is_present)
        .fetch_one(pool.as_ref())
        .await?;

        Ok(attendance)
    }
    
    async fn mark_attendance(
        &self,
        ctx: &Context<'_>,
        id: i32,
        date: NaiveDate,
        is_present: bool,
        hmac_signature: String, 
    ) -> Result<Attendance,sqlx::Error> {
        
        let pool = ctx.data::<Arc<PgPool>>().expect("Pool not found in context");

        let secret_key = ctx.data::<String>().expect("HMAC secret not found in context");

        let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");

        let message = format!("{}{}{}", id, date, is_present);
        mac.update(message.as_bytes());

        let expected_signature = mac.finalize().into_bytes();
        
      
        // Convert the received HMAC signature from the client to bytes for comparison
        let received_signature = hex::decode(hmac_signature)
            .map_err(|_| sqlx::Error::Protocol("Invalid HMAC signature".into()))?;
        

        if expected_signature.as_slice() != received_signature.as_slice() {
            
            return Err(sqlx::Error::Protocol("HMAC verification failed".into()));
        }

        let current_time = Local::now().with_timezone(&Kolkata).time();

        let prev_date = date - Duration::days(1);
    
        let prev_attendance: Option<Attendance> = sqlx::query_as::<_, Attendance>(
            "SELECT * FROM Attendance WHERE id = $1 AND date = $2"
        )
        .bind(id)
        .bind(prev_date)
        .fetch_optional(pool.as_ref())
        .await?;
    
        // Get member details to update streaks
        let mut member: Member = sqlx::query_as::<_, Member>(
            "SELECT * FROM Member WHERE id = $1"
        )
        .bind(id)
        .fetch_one(pool.as_ref())
        .await?;
    
        if is_present {
            if let Some(prev_attendance) = prev_attendance {
                // continue streak if present yesterday
                if prev_attendance.is_present {
                    member.streak += 1;
                } else {
                    member.streak = 1;
                }
            } else {
                member.streak = 1; // new streak if no previous update
            }
    
            if member.streak > member.max_streak {
                member.max_streak = member.streak;
            }
        } else {
            member.streak = 0;
        }
    
        sqlx::query(
            "UPDATE Member SET streak = $1, max_streak = $2 WHERE id = $3"
        )
        .bind(member.streak)
        .bind(member.max_streak)
        .bind(id)
        .execute(pool.as_ref())
        .await?;

        let attendance = sqlx::query_as::<_, Attendance>(
            "
            UPDATE Attendance
            SET 
                timein = CASE WHEN timein = '00:00:00' THEN $1 ELSE timein END,
                timeout = $1,
                is_present = $2
            WHERE id = $3 AND date = $4
            RETURNING *
            "
        )
        .bind(current_time)
        .bind(is_present)
        .bind(id)
        .bind(date)
        .fetch_one(pool.as_ref())
        .await?;

        Ok(attendance)
    }
}
