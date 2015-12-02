package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class PaymentChannelServerState {
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

    /**
     * Gets the highest payment to ourselves (which we will receive on settle(), not including fees)
     */
    public synchronized Coin getBestValueToMe() {
        return bestValueToMe;
    }

    protected synchronized void updateChannelInWallet() {
        if (storedServerChannel != null) {
            storedServerChannel.updateValueToMe(bestValueToMe, bestValueSignature);
            StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                    wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
            channels.updatedChannel(storedServerChannel);
        }
    }
}
