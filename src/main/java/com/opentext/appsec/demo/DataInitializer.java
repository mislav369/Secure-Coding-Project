package com.opentext.appsec.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.opentext.appsec.demo.model.User;
import com.opentext.appsec.demo.model.Payment;
import com.opentext.appsec.demo.model.Transaction;
import com.opentext.appsec.demo.repository.UserRepository;
import com.opentext.appsec.demo.repository.PaymentRepository;
import com.opentext.appsec.demo.repository.TransactionRepository;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Data initializer for demo purposes.
 */
@Configuration
public class DataInitializer {

    private static final Log logger = LogFactory.getLog(DataInitializer.class);

    private static final String ACTIVE_STATUS = "ACTIVE";

    @Value("${seed.admin.password}")
    private String adminPassword;

    @Value("${seed.user.password}")
    private String userPassword;

    @Value("${seed.john.password}")
    private String johnPassword;

    @Value("${seed.alice.password}")
    private String alicePassword;

    @Bean
    @Order(1)
    CommandLineRunner initDatabase(UserRepository repository, PasswordEncoder passwordEncoder) {
        return args -> {
            repository.save(new User("admin", passwordEncoder.encode(adminPassword), "admin@example.com", "ADMIN"));
            repository.save(new User("user",  passwordEncoder.encode(userPassword),  "user@example.com",  "USER"));
            repository.save(new User("john",  passwordEncoder.encode(johnPassword),  "john@example.com",  "USER"));
            repository.save(new User("alice", passwordEncoder.encode(alicePassword), "alice@example.com", "USER"));
        };
    }

    @Bean
    @Order(2)
    CommandLineRunner initPayments(PaymentRepository paymentRepository, UserRepository userRepository, TransactionRepository transactionRepository) {
        return args -> {
            // INSECURE (intentional): sample payment data includes plain-text card numbers and CVV for demo purposes.
            try {
                User user = userRepository.findByUsername("user");
                if (user != null) {
                    paymentRepository.save(new Payment(user.getId(), "CREDIT_CARD", "4111111111111111", "12/25", "123", null, ACTIVE_STATUS));
                    logger.info("Seeded credit card for user 'user' id=" + user.getId());
                }
                User john = userRepository.findByUsername("john");
                if (john != null) {
                    paymentRepository.save(new Payment(john.getId(), "PAYPAL", null, null, null, "john.paypal@example.com", ACTIVE_STATUS));
                    logger.info("Seeded PayPal for 'john' id=" + john.getId());
                }
                User alice = userRepository.findByUsername("alice");
                if (alice != null) {
                    // keep an example credit card and also add a PayPal account for alice
                    paymentRepository.save(new Payment(alice.getId(), "CREDIT_CARD", "5555555555554444", "01/26", "999", null, "INACTIVE"));
                    paymentRepository.save(new Payment(alice.getId(), "PAYPAL", null, null, null, "alice.paypal@example.com", ACTIVE_STATUS));
                }
            } catch (Exception e) {
                logger.error("Error seeding payments", e);
            }
            try {
                for (Payment payment
                        : paymentRepository.findAll()) {

                    seedTransactionsForPayment(
                            payment,
                            transactionRepository);
                }
            } catch (Exception exception) {
                logger.error(
                        "Error seeding transactions",
                        exception);
            }
        };
    }

    private void seedTransactionsForPayment(
            Payment payment,
            TransactionRepository transactionRepository) {

        try {
            logger.info(
                    "Seeding transactions for payment id="
                            + payment.getId()
                            + " userId="
                            + payment.getUserId());

            Transaction firstTransaction =
                    new Transaction(
                            payment.getId(),
                            12.34,
                            "APPROVED");

            Transaction secondTransaction =
                    new Transaction(
                            payment.getId(),
                            5.00,
                            "APPROVED");

            Transaction thirdTransaction =
                    new Transaction(
                            payment.getId(),
                            2.50,
                            "DECLINED");

            transactionRepository.save(firstTransaction);
            transactionRepository.save(secondTransaction);
            transactionRepository.save(thirdTransaction);

            logger.info(
                    "Saved 3 transactions for payment id="
                            + payment.getId());
        } catch (Exception exception) {
            logger.error(
                    "Failed to seed transactions for payment id="
                            + payment.getId(),
                    exception);
        }
    }
}
