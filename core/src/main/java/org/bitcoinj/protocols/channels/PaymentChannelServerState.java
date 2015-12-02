package org.bitcoinj.protocols.channels;

import com.google.common.util.concurrent.ListenableFuture;
import org.bitcoinj.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>A payment channel is a method of sending money to someone such that the amount of money you send can be adjusted
 * after the fact, in an efficient manner that does not require broadcasting to the network. This can be used to
 * implement micropayments or other payment schemes in which immediate settlement is not required, but zero trust
 * negotiation is. Note that this class only allows the amount of money received to be incremented, not decremented.</p>
 *
 * <p>This class implements the core state machine for the server side of the protocol. The client side is implemented
 * by {@link PaymentChannelClientState} and {@link PaymentChannelServerListener} implements the server-side network
 * protocol listening for TCP/IP connections and moving this class through each state. We say that the party who is
 * sending funds is the <i>client</i> or <i>initiating party</i>. The party that is receiving the funds is the
 * <i>server</i> or <i>receiving party</i>. Although the underlying Bitcoin protocol is capable of more complex
 * relationships than that, this class implements only the simplest case.</p>
 *
 * <p>To protect clients from malicious servers, a channel has an expiry parameter. When this expiration is reached, the
 * client will broadcast the created refund  transaction and take back all the money in this channel. Because this is
 * specified in terms of block timestamps, it is fairly fuzzy and it is possible to spend the refund transaction up to a
 * few hours before the actual timestamp. Thus, it is very important that the channel be closed with plenty of time left
 * to get the highest value payment transaction confirmed before the expire time (minimum 3-4 hours is suggested if the
 * payment transaction has enough fee to be confirmed in the next block or two).</p>
 *
 * <p>To begin, we must provide the client with a pubkey which we wish to use for the multi-sig contract which locks in
 * the channel. The client will then provide us with an incomplete refund transaction and the pubkey which they used in
 * the multi-sig contract. We use this pubkey to recreate the multi-sig output and then sign that to the refund
 * transaction. We provide that signature to the client and they then have the ability to spend the refund transaction
 * at the specified expire time. The client then provides us with the full, signed multi-sig contract which we verify
 * and broadcast, locking in their funds until we spend a payment transaction or the expire time is reached. The client
 * can then begin paying by providing us with signatures for the multi-sig contract which pay some amount back to the
 * client, and the rest is ours to do with as we wish.</p>
 */
public abstract class PaymentChannelServerState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelServerState.class);

    // Package-local for checkArguments in StoredServerChannel
    final Wallet wallet;

    // The object that will broadcast transactions for us - usually a peer group.
    protected final TransactionBroadcaster broadcaster;

    // The last signature the client provided for a payment transaction.
    protected byte[] bestValueSignature;

    protected Coin bestValueToMe = Coin.ZERO;

    // The server key for the multi-sig contract
    // We currently also use the serverKey for payouts, but this is not required
    protected ECKey serverKey;

    protected long minExpireTime;

    protected StoredServerChannel storedServerChannel = null;

    PaymentChannelServerState(StoredServerChannel storedServerChannel, Wallet wallet, TransactionBroadcaster broadcaster) throws VerificationException {
        synchronized (storedServerChannel) {
            this.wallet = checkNotNull(wallet);
            this.broadcaster = checkNotNull(broadcaster);
            this.serverKey = checkNotNull(storedServerChannel.myKey);
            this.storedServerChannel = storedServerChannel;
            this.bestValueToMe = checkNotNull(storedServerChannel.bestValueToMe);
            this.bestValueSignature = storedServerChannel.bestValueSignature;
            checkArgument(bestValueToMe.equals(Coin.ZERO) || bestValueSignature != null);
            storedServerChannel.state = this;
        }
    }

    /**
     * Creates a new state object to track the server side of a payment channel.
     *
     * @param broadcaster The peer group which we will broadcast transactions to, this should have multiple peers
     * @param wallet The wallet which will be used to complete transactions
     * @param serverKey The private key which we use for our part of the multi-sig contract
     *                  (this MUST be fresh and CANNOT be used elsewhere)
     * @param minExpireTime The earliest time at which the client can claim the refund transaction (UNIX timestamp of block)
     */
    public PaymentChannelServerState(TransactionBroadcaster broadcaster, Wallet wallet, ECKey serverKey, long minExpireTime) {
        this.serverKey = checkNotNull(serverKey);
        this.wallet = checkNotNull(wallet);
        this.broadcaster = checkNotNull(broadcaster);
        this.minExpireTime = minExpireTime;
    }

    public abstract int getMajorVersion();

    /**
     * Returns true if the state machine is in the closed state
     * @return
     */
    public abstract boolean isClosed();

    /**
     * Gets the highest payment to ourselves (which we will receive on settle(), not including fees)
     */
    public synchronized Coin getBestValueToMe() {
        return bestValueToMe;
    }

    /**
     * Gets the fee paid in the final payment transaction (only available if settle() did not throw an exception)
     */
    public abstract Coin getFeePaid();

    protected synchronized void updateChannelInWallet() {
        if (storedServerChannel != null) {
            storedServerChannel.updateValueToMe(bestValueToMe, bestValueSignature);
            StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                    wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
            channels.updatedChannel(storedServerChannel);
        }
    }

    /**
     * Stores this channel's state in the wallet as a part of a {@link StoredPaymentChannelServerStates} wallet
     * extension and keeps it up-to-date each time payment is incremented. This will be automatically removed when
     * a call to {@link PaymentChannelV1ServerState#close()} completes successfully. A channel may only be stored after it
     * has fully opened (ie state == State.READY).
     *
     * @param connectedHandler Optional {@link PaymentChannelServer} object that manages this object. This will
     *                         set the appropriate pointer in the newly created {@link StoredServerChannel} before it is
     *                         committed to wallet. If set, closing the state object will propagate the close to the
     *                         handler which can then do a TCP disconnect.
     */
    public abstract void storeChannelInWallet(@Nullable PaymentChannelServer connectedHandler);

    /**
     * Called when the client provides the contract. Checks that the contract is valid.
     *
     * @param contract The provided contract. Do not mutate this object after this call.
     * @return A future which completes when the provided multisig contract successfully broadcasts, or throws if the broadcast fails for some reason
     *         Note that if the network simply rejects the transaction, this future will never complete, a timeout should be used.
     * @throws VerificationException If the provided multisig contract is not well-formed or does not meet previously-specified parameters
     */
    public abstract ListenableFuture<PaymentChannelV1ServerState> provideContract(final Transaction contract) throws VerificationException;

    /**
     * Called when the client provides us with a new signature and wishes to increment total payment by size.
     * Verifies the provided signature and only updates values if everything checks out.
     * If the new refundSize is not the lowest we have seen, it is simply ignored.
     *
     * @param refundSize How many satoshis of the original contract are refunded to the client (the rest are ours)
     * @param signatureBytes The new signature spending the multi-sig contract to a new payment transaction
     * @throws VerificationException If the signature does not verify or size is out of range (incl being rejected by the network as dust).
     * @return true if there is more value left on the channel, false if it is now fully used up.
     */
    public abstract boolean incrementPayment(Coin refundSize, byte[] signatureBytes) throws VerificationException, ValueOutOfRangeException, InsufficientMoneyException;

    /**
     * Gets the multisig contract which was used to initialize this channel
     */
    public abstract Transaction getContract();

    /**
     * <p>Closes this channel and broadcasts the highest value payment transaction on the network.</p>
     *
     * @return a future which completes when the provided multisig contract successfully broadcasts, or throws if the
     *         broadcast fails for some reason. Note that if the network simply rejects the transaction, this future
     *         will never complete, a timeout should be used.
     * @throws InsufficientMoneyException If the payment tx would have cost more in fees to spend than it is worth.
     */
    public abstract ListenableFuture<Transaction> close() throws InsufficientMoneyException;
}
