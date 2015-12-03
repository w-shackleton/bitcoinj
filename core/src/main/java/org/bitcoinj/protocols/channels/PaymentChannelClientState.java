package org.bitcoinj.protocols.channels;

import com.google.common.base.Throwables;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.utils.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkNotNull;

public abstract class PaymentChannelClientState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelClientState.class);

    final Wallet wallet;

    // Both sides need a key (private in our case, public for the server) in order to manage the multisig contract
    // and transactions that spend it.
    final ECKey myKey, serverMultisigKey;

    // The id of this channel in the StoredPaymentChannelClientStates, or null if it is not stored
    protected StoredClientChannel storedChannel;

    PaymentChannelClientState(StoredClientChannel storedClientChannel, Wallet wallet) throws VerificationException {
        this.wallet = checkNotNull(wallet);
        this.myKey = checkNotNull(storedClientChannel.myKey);
        this.serverMultisigKey = null;
        this.storedChannel = storedClientChannel;
    }

    /**
     * Creates a state object for a payment channel client. It is expected that you be ready to
     * {@link PaymentChannelV1ClientState#initiate()} after construction (to avoid creating objects for channels which are
     * not going to finish opening) and thus some parameters provided here are only used in
     * {@link PaymentChannelV1ClientState#initiate()} to create the Multisig contract and refund transaction.
     *
     * @param wallet a wallet that contains at least the specified amount of value.
     * @param myKey a freshly generated private key for this channel.
     * @param serverMultisigKey a public key retrieved from the server used for the initial multisig contract
     * @param value how many satoshis to put into this contract. If the channel reaches this limit, it must be closed.
     *              It is suggested you use at least {@link Coin#CENT} to avoid paying fees if you need to spend the refund transaction
     * @param expiryTimeInSeconds At what point (UNIX timestamp +/- a few hours) the channel will expire
     *
     * @throws VerificationException If either myKey's pubkey or serverMultisigKey's pubkey are non-canonical (ie invalid)
     */
    public PaymentChannelClientState(Wallet wallet, ECKey myKey, ECKey serverMultisigKey,
                                     Coin value, long expiryTimeInSeconds) throws VerificationException {
        this.wallet = checkNotNull(wallet);
        this.serverMultisigKey = checkNotNull(serverMultisigKey);
        this.myKey = checkNotNull(myKey);
    }

    public abstract int getMajorVersion();

    public abstract boolean isClosed();

    /**
     * Creates the initial multisig contract and incomplete refund transaction which can be requested at the appropriate
     * time using {@link PaymentChannelV1ClientState#getIncompleteRefundTransaction} and
     * {@link PaymentChannelV1ClientState#getMultisigContract()}. The way the contract is crafted can be adjusted by
     * overriding {@link PaymentChannelV1ClientState#editContractSendRequest(org.bitcoinj.core.Wallet.SendRequest)}.
     * By default unconfirmed coins are allowed to be used, as for micropayments the risk should be relatively low.
     *
     * @throws ValueOutOfRangeException if the value being used is too small to be accepted by the network
     * @throws InsufficientMoneyException if the wallet doesn't contain enough balance to initiate
     */
    public void initiate() throws ValueOutOfRangeException, InsufficientMoneyException {
        initiate(null);
    }

    /**
     * Creates the initial multisig contract and incomplete refund transaction which can be requested at the appropriate
     * time using {@link PaymentChannelV1ClientState#getIncompleteRefundTransaction} and
     * {@link PaymentChannelV1ClientState#getMultisigContract()}. The way the contract is crafted can be adjusted by
     * overriding {@link PaymentChannelV1ClientState#editContractSendRequest(org.bitcoinj.core.Wallet.SendRequest)}.
     * By default unconfirmed coins are allowed to be used, as for micropayments the risk should be relatively low.
     * @param userKey Key derived from a user password, needed for any signing when the wallet is encrypted.
     *                  The wallet KeyCrypter is assumed.
     *
     * @throws ValueOutOfRangeException   if the value being used is too small to be accepted by the network
     * @throws InsufficientMoneyException if the wallet doesn't contain enough balance to initiate
     */
    public abstract void initiate(@Nullable KeyParameter userKey) throws ValueOutOfRangeException, InsufficientMoneyException;

    protected void watchCloseConfirmations() {
        // When we see the close transaction get enough confirmations, we can just delete the record
        // of this channel along with the refund tx from the wallet, because we're not going to need
        // any of that any more.
        final TransactionConfidence confidence = storedChannel.close.getConfidence();
        int numConfirms = Context.get().getEventHorizon();
        ListenableFuture<TransactionConfidence> future = confidence.getDepthFuture(numConfirms, Threading.SAME_THREAD);
        Futures.addCallback(future, new FutureCallback<TransactionConfidence>() {
            @Override
            public void onSuccess(TransactionConfidence result) {
                deleteChannelFromWallet();
            }

            @Override
            public void onFailure(Throwable t) {
                Throwables.propagate(t);
            }
        });
    }

    private synchronized void deleteChannelFromWallet() {
        log.info("Close tx has confirmed, deleting channel from wallet: {}", storedChannel);
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        channels.removeChannel(storedChannel);
        storedChannel = null;
    }

    protected abstract Coin getValueToMe();

    /**
     * Returns the amount of money sent on this channel so far.
     */
    public synchronized Coin getValueSpent() {
        return getTotalValue().subtract(getValueRefunded());
    }

    /**
     * Gets the contract which was used to initialize this channel
     */
    public abstract Transaction getContract();

    /**
     * <p>Updates the outputs on the payment contract transaction and re-signs it. The state must be READY in order to
     * call this method. The signature that is returned should be sent to the server so it has the ability to broadcast
     * the best seen payment when the channel closes or times out.</p>
     *
     * <p>The returned signature is over the payment transaction, which we never have a valid copy of and thus there
     * is no accessor for it on this object.</p>
     *
     * <p>To spend the whole channel increment by {@link PaymentChannelV1ClientState#getTotalValue()} -
     * {@link PaymentChannelV1ClientState#getValueRefunded()}</p>
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @throws ValueOutOfRangeException If size is negative or the channel does not have sufficient money in it to
     *                                  complete this payment.
     */
    public abstract IncrementedPayment incrementPaymentBy(Coin size, @Nullable KeyParameter userKey) throws ValueOutOfRangeException;

    protected synchronized void updateChannelInWallet() {
        if (storedChannel == null)
            return;
        storedChannel.valueToMe = getValueToMe();
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        channels.updatedChannel(storedChannel);
    }

    /**
     * Sets this channel's state in {@link StoredPaymentChannelClientStates} to unopened so this channel can be reopened
     * later.
     *
     * @see PaymentChannelV1ClientState#storeChannelInWallet(Sha256Hash)
     */
    public synchronized void disconnectFromChannel() {
        if (storedChannel == null)
            return;
        synchronized (storedChannel) {
            storedChannel.active = false;
        }
    }

    /**
     * <p>Stores this channel's state in the wallet as a part of a {@link StoredPaymentChannelClientStates} wallet
     * extension and keeps it up-to-date each time payment is incremented. This allows the
     * {@link StoredPaymentChannelClientStates} object to keep track of timeouts and broadcast the refund transaction
     * when the channel expires.</p>
     *
     * <p>A channel may only be stored after it has fully opened (ie state == State.READY). The wallet provided in the
     * constructor must already have a {@link StoredPaymentChannelClientStates} object in its extensions set.</p>
     *
     * @param id A hash providing this channel with an id which uniquely identifies this server. It does not have to be
     *           unique.
     */
    public abstract void storeChannelInWallet(Sha256Hash id);

    /** Container for a signature and an amount that was sent. */
    public static class IncrementedPayment {
        public TransactionSignature signature;
        public Coin amount;
    }

    /**
     * Gets the total value of this channel (ie the maximum payment possible)
     */
    public abstract Coin getTotalValue();

    /**
     * Gets the current amount refunded to us from the multisig contract (ie totalValue-valueSentToServer)
     */
    public abstract Coin getValueRefunded();

    /**
     * Returns true if the tx is a valid settlement transaction.
     */
    public synchronized boolean isSettlementTransaction(Transaction tx) {
        try {
            tx.verify();
            tx.getInput(0).verify(getContract().getOutput(0));
            return true;
        } catch (VerificationException e) {
            return false;
        }
    }
}
