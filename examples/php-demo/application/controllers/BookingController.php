<?php
// Demo controller with intentional production issues (for Phase 3 testing).

class BookingController extends CI_Controller
{
    public function create()
    {
        // ISSUE: no input validation, no error handling around the model call.
        $date = $_GET['date'];
        $userId = $_POST['user_id'];

        $this->load->model('BookingModel');
        $booking = $this->BookingModel->createBooking($userId, $date);

        echo json_encode($booking);
    }

    public function cancel()
    {
        try {
            $id = $_GET['id'];
            $this->BookingModel->cancel($id);
        } catch (Exception $e) {
            // ISSUE: empty catch block swallows the error silently.
        }
    }
}
