package com.opentext.appsec.demo.controller;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.opentext.appsec.demo.model.Payment;
import com.opentext.appsec.demo.model.Transaction;
import com.opentext.appsec.demo.repository.PaymentRepository;
import com.opentext.appsec.demo.repository.TransactionRepository;


import java.util.List;
import java.time.LocalDateTime;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;

import com.opentext.appsec.demo.dto.PaymentRequest;

import java.time.ZoneOffset;

/**
 * Payment controller exposing insecure demo endpoints.
 */
@RestController
@RequestMapping("/api/payments")
public class PaymentController {

    private static final Log logger = LogFactory.getLog(PaymentController.class);

    private static final String CREDIT_CARD_TYPE = "CREDIT_CARD";

    private final PaymentRepository paymentRepository;
    private final TransactionRepository transactionRepository;

    public PaymentController(
            PaymentRepository paymentRepository,
            TransactionRepository transactionRepository) {
        this.paymentRepository = paymentRepository;
        this.transactionRepository = transactionRepository;
    }

    /**
     * Get all payments - returns full payment details including card numbers and CVV in plain text for demo purposes.
     */
    @Operation(summary = "Get all payments (INSECURE: exposes sensitive data)")
    @GetMapping
    public List<Payment> getAllPayments() {
        // INSECURE (intentional): returns full `Payment` objects including payment PAN and CVV in plain text.
        return paymentRepository.findAll();
    }

    /**
     * Get payments by user id - returns full payment details including card numbers and CVV in plain text for demo purposes.
     */
    @Operation(summary = "Get payments by user id")
    @GetMapping("/user/{userId}")
    public List<Payment> getByUser(@Parameter(description = "User id") @PathVariable Long userId) {
        return paymentRepository.findByUserId(userId);
    }

    /**
     * Create a payment method - accepts and stores card data in plain text for demo purposes.
     */
    @Operation(summary = "Create a payment method")
    @PostMapping
    public Payment createPayment(@RequestBody PaymentRequest request) {
        // Map only the client-provided fields onto a new entity to prevents mass assignment
        Payment payment = new Payment();
        payment.setUserId(request.userId());
        payment.setType(request.type());
        payment.setCardNumber(request.cardNumber());
        payment.setCardExpiry(request.cardExpiry());
        payment.setCvv(request.cvv());
        payment.setPaypalEmail(request.paypalEmail());

        if (payment.getType() != null) {
            String t = payment.getType().toUpperCase();
            if (t.equals("CARD") || t.equals(CREDIT_CARD_TYPE)) {
                payment.setType(CREDIT_CARD_TYPE);
            }
            else if (t.equals("PAYPAL")) payment.setType("PAYPAL");
            else payment.setType(t);
        } else {
            payment.setType(CREDIT_CARD_TYPE);
        }

        payment.setStatus("ACTIVE");
        payment.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));

        return paymentRepository.save(payment);
    }

    /**
     * Delete a payment method by id.
     */
    @Operation(summary = "Delete a payment method")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePayment(@PathVariable Long id){
        if (!paymentRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        paymentRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }

    /**
     * Simulate charging a payment method - logs sensitive card data for demo purposes.
     */
    @Operation(summary = "Simulate charging a payment (insecure demo)")
    @PostMapping("/charge")
    public ResponseEntity<String> chargePayment(@Parameter(description = "Payment id to charge") @RequestParam Long paymentId,
                                                @Parameter(description = "Amount") @RequestParam double amount) {
        Payment p = paymentRepository.findById(paymentId).orElse(null);
        if (p == null) {
            return ResponseEntity.notFound().build();
        }
        // INSECURE (intentional): logging sensitive card data and simulating a charge
        String debug = "Charging payment id=" + paymentId + " card=" + p.getCardNumber() + " amount=" + amount;
        logger.debug(debug);

        // Persist a simulated transaction record so transactions can be listed
        Transaction tx = new Transaction(paymentId, amount, "APPROVED");
        transactionRepository.save(tx);

        return ResponseEntity.ok(debug);
    }

    /**
     * Debug endpoint that lists raw card numbers for all payments - demonstrates insecure handling of sensitive data.
     */
    @Operation(summary = "Debug endpoint showing raw card numbers (INSECURE - demo)")
    @GetMapping("/debug/rawcards")
    public String listRawCards() {
        // INSECURE (intentional): exposes full payment PANs in responses.
        StringBuilder sb = new StringBuilder();
        for (Payment p : paymentRepository.findAll()) {
            sb.append("paymentId=").append(p.getId()).append(" card=").append(p.getCardNumber()).append("\n");
        }
        return sb.toString();
    }
}
