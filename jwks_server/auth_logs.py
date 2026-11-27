from jwks_server.database import DB_PATH, get_connection


def log_auth_request(request_ip, username=None, db_path=DB_PATH):
    """Record an authentication request in the database."""

    connection = get_connection(db_path)

    try:
        user_id = None

        # Find the registered user's ID.
        if username:
            user = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if user is not None:
                user_id = user["id"]

        # Store the authentication request.
        connection.execute(
            """
            INSERT INTO auth_logs (request_ip, user_id)
            VALUES (?, ?)
            """,
            (request_ip, user_id),
        )

        connection.commit()

    finally:
        connection.close()