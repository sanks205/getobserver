<?php
// Demo service class (categorized as a Service by Observer).

class PaymentService
{
    public function charge($amount, $token)
    {
        // ISSUE: no null check on $token; possible null reference at runtime.
        return $this->gateway->charge($token->id, $amount);
    }
}
