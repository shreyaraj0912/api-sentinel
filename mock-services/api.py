from fastapi import FastAPI


app = FastAPI(
    title="API-Sentinel Mock API",
    description="Local API used for security detection simulations",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "message": "API-Sentinel Mock API Running"
    }


# ---------------------------------------------------------
# Normal user endpoint
# ---------------------------------------------------------

@app.get("/api/profile")
def get_profile():
    return {
        "user": "demo-user",
        "role": "USER",
        "message": "Profile endpoint"
    }


# ---------------------------------------------------------
# User/object endpoint
# Used for BOLA simulation
# ---------------------------------------------------------

@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    return {
        "user_id": user_id,
        "name": f"User {user_id}"
    }


# ---------------------------------------------------------
# Privileged endpoint
# Used for BFLA simulation
# ---------------------------------------------------------

@app.delete("/api/users/{user_id}")
def delete_user(user_id: int):
    return {
        "message": f"User {user_id} deleted"
    }


# ---------------------------------------------------------
# Normal login endpoint
# Used by Shadow API detector as a known endpoint
# ---------------------------------------------------------

@app.post("/api/login")
def login():
    return {
        "message": "Login successful"
    }


# ---------------------------------------------------------
# Undocumented endpoint
# Used for Shadow API simulation
# ---------------------------------------------------------

@app.get("/api/internal/debug")
def internal_debug():
    return {
        "debug": True,
        "message": "Internal debug endpoint"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=9000,
    )