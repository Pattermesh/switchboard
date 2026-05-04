// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title AgentEscrow
 * @notice Escrow contract for agent-to-agent payments with timeout and refund.
 * @dev Implements a payment protocol:
 *   1. Payer creates escrow with payment + timeout
 *   2. Agent performs work off-chain
 *   3. Payer confirms → funds released to payee
 *   4. Timeout expires → payer can reclaim (after challenge period)
 *
 * Hardening (kcolb/testnet-hardening):
 *   - registerAgent is now onlyOwner (was permissionless — security bug).
 *   - confirmPayment / requestRefund / cancelPayment are nonReentrant — they perform
 *     external ETH transfers via low-level call.
 *   - State transitions follow checks-effects-interactions; the nonReentrant guard is
 *     defense in depth.
 */
contract AgentEscrow is Ownable, ReentrancyGuard {
    enum State {
        Created,
        Locked,
        Confirmed,
        Released,
        Refunded,
        Cancelled
    }

    struct Payment {
        address payer;
        address payee;
        uint256 amount;
        uint256 timeoutBlocks; // blocks until auto-expire
        uint256 challengePeriod; // blocks payer must wait to reclaim after timeout
        State state;
        string requestId; // off-chain payment request ID
        uint256 createdAt;
    }

    uint256 public immutable chainId;

    // requestId → Payment
    mapping(string => Payment) public payments;

    // Owner-curated allowlist of trusted agent addresses. Off-chain consumers (e.g.
    // discovery / reputation services) can read this; the contract itself does not
    // gate state-changing functions on registry membership today, but the allowlist
    // is preserved as a public source of truth for tooling.
    mapping(address => bool) public registeredAgents;

    // Events
    event PaymentCreated(string indexed requestId, address indexed payer, address indexed payee, uint256 amount);
    event PaymentLocked(string indexed requestId);
    event PaymentConfirmed(string indexed requestId, address indexed payer);
    event PaymentReleased(string indexed requestId, address indexed payee, uint256 amount);
    event PaymentRefunded(string indexed requestId, address indexed payer, uint256 amount);
    event PaymentCancelled(string indexed requestId, address indexed payer, uint256 amount);
    event AgentRegistered(address indexed agent);
    event AgentDeregistered(address indexed agent);

    constructor(uint256 _chainId) Ownable(msg.sender) {
        chainId = _chainId;
    }

    /**
     * @notice Register an agent address. Permissioned: only the contract owner.
     * @dev Previously permissionless — a known bug fixed in kcolb/testnet-hardening.
     */
    function registerAgent(address agent) external onlyOwner {
        require(agent != address(0), "agent cannot be zero address");
        registeredAgents[agent] = true;
        emit AgentRegistered(agent);
    }

    /**
     * @notice Deregister a previously registered agent.
     */
    function deregisterAgent(address agent) external onlyOwner {
        registeredAgents[agent] = false;
        emit AgentDeregistered(agent);
    }

    /**
     * @notice Create a payment request and lock funds in escrow
     * @param requestId Unique off-chain request ID
     * @param payee Recipient agent address
     * @param timeoutBlocks Blocks until the payment can be auto-expired
     * @param challengePeriod Blocks payer must wait after timeout to reclaim
     */
    function createPayment(string calldata requestId, address payee, uint256 timeoutBlocks, uint256 challengePeriod)
        external
        payable
        returns (bool)
    {
        require(msg.value > 0, "Must send ETH");
        require(bytes(requestId).length > 0, "requestId cannot be empty");
        require(payee != address(0), "payee cannot be zero address");
        require(payments[requestId].createdAt == 0, "requestId already exists");
        require(timeoutBlocks > 0, "timeoutBlocks must be > 0");

        payments[requestId] = Payment({
            payer: msg.sender,
            payee: payee,
            amount: msg.value,
            timeoutBlocks: timeoutBlocks,
            challengePeriod: challengePeriod,
            state: State.Locked,
            requestId: requestId,
            createdAt: block.number
        });

        emit PaymentCreated(requestId, msg.sender, payee, msg.value);
        emit PaymentLocked(requestId);
        return true;
    }

    /**
     * @notice Payer confirms work is done → release funds to payee
     * @dev Can only be called by the original payer. Only in Locked state.
     */
    function confirmPayment(string calldata requestId) external nonReentrant returns (bool) {
        Payment storage p = payments[requestId];
        require(p.payer == msg.sender, "Only payer can confirm");
        require(p.state == State.Locked, "Payment not in Locked state");
        require(block.number < p.createdAt + p.timeoutBlocks, "Payment has expired");

        uint256 amount = p.amount;
        address payee = p.payee;
        p.state = State.Released;
        p.amount = 0;

        emit PaymentConfirmed(requestId, msg.sender);
        emit PaymentReleased(requestId, payee, amount);

        (bool success,) = payee.call{value: amount}("");
        require(success, "Transfer to payee failed");
        return true;
    }

    /**
     * @notice Payer requests refund after timeout + challenge period
     * @dev After timeout expires AND challenge period passes, payer can reclaim.
     */
    function requestRefund(string calldata requestId) external nonReentrant returns (bool) {
        Payment storage p = payments[requestId];
        require(p.payer == msg.sender, "Only payer can request refund");
        require(p.state == State.Locked, "Payment not in Locked state");
        require(block.number >= p.createdAt + p.timeoutBlocks + p.challengePeriod, "Challenge period not over");

        uint256 amount = p.amount;
        address payer = p.payer;
        p.state = State.Refunded;
        p.amount = 0;

        emit PaymentRefunded(requestId, payer, amount);

        (bool success,) = payer.call{value: amount}("");
        require(success, "Refund transfer failed");
        return true;
    }

    /**
     * @notice Cancel a payment before timeout (mutual agreement)
     */
    function cancelPayment(string calldata requestId) external nonReentrant returns (bool) {
        Payment storage p = payments[requestId];
        require(p.payer == msg.sender, "Only payer can cancel");
        require(p.state == State.Locked, "Payment not in Locked state");

        uint256 amount = p.amount;
        address payer = p.payer;
        p.state = State.Cancelled;
        p.amount = 0;

        emit PaymentCancelled(requestId, payer, amount);

        (bool success,) = payer.call{value: amount}("");
        require(success, "Cancel refund failed");
        return true;
    }

    /**
     * @notice Get payment details
     */
    function getPayment(string calldata requestId) external view returns (Payment memory) {
        return payments[requestId];
    }

    /**
     * @notice Check if a payment is in a given state
     */
    function isState(string calldata requestId, State expected) external view returns (bool) {
        return payments[requestId].state == expected;
    }

    /**
     * @notice Check if a payment has expired (timeout passed but not yet in refundable window)
     */
    function isExpired(string calldata requestId) external view returns (bool) {
        Payment storage p = payments[requestId];
        if (p.createdAt == 0) return false;
        return block.number >= p.createdAt + p.timeoutBlocks && p.state == State.Locked;
    }
}
