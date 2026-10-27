def load(db, kanja_id):
    return db.query("SELECT * FROM monshin_hyo WHERE kanja_id = %s", (kanja_id,))

def karte_for(patient_id, clinic_id):
    return {"patient_id": patient_id, "clinic_id": clinic_id}
