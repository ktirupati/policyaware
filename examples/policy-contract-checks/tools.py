def crm_read_customer(customer_id: str) -> dict:
    return {"customer_id": customer_id}


def crm_update_customer(customer_id: str, email: str) -> dict:
    return {"customer_id": customer_id, "email": email}

