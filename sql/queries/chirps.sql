-- name: CreateChirp :one
INSERT INTO
    chirps (id, created_at, updated_at, body, user_id)
VALUES
    (gen_random_uuid (), NOW (), NOW (), $1, $2)
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps
ORDER BY created_at ASC;

-- name: GetChirpByID :one
SELECT * FROM chirps
WHERE id = $1;

-- name: GetChirpsByUserID :many
SELECT * FROM chirps
WHERE user_id = $1
    AND EXISTS (SELECT 1 FROM users WHERE users.id = chirps.user_id)
ORDER BY created_at ASC;

-- name: DeleteChirpByID :exec
DELETE FROM chirps
WHERE id = $1;