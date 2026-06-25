<?php
// Demo model with intentional issues (for Phase 3 testing).

class BookingModel extends CI_Model
{
    // ISSUE: hardcoded credentials / exposed secret.
    private $apiKey = "sk_live_EXAMPLEfakekey"; // demo placeholder — not a real secret

    public function createBooking($userId, $date)
    {
        // ISSUE: raw SQL built via string concatenation -> SQL injection risk.
        $sql = "INSERT INTO bookings (user_id, booking_date) VALUES ('" . $userId . "', '" . $date . "')";
        return $this->db->query($sql);
    }

    public function findByDate($date)
    {
        // ISSUE: full table scan; booking_date likely missing an index ->
        // performance problem on large tables during peak traffic.
        $sql = "SELECT * FROM bookings WHERE booking_date = '" . $date . "'";
        return $this->db->query($sql)->result();
    }

    public function cancel($id)
    {
        $sql = "DELETE FROM bookings WHERE id = " . $id;
        return $this->db->query($sql);
    }
}
