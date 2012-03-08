# encoding: utf-8
require 'jr'

module Bitcoin
	# Errors that the bitcoind is expected to raise should derive from this class.
	class Error < Exception
	end

	# InvalidAddress is raised when a bitcoin address is invalid.
	class InvalidAddress < Error
		# This is the address that was invalid.
		attr_reader :address

		def initialize(address)
			@address = address.freeze
			super("Invalid bitcoin address: #{@address.inspect}")
		end
	end

	# UnknownPrivateKey is raised when we need, but don't have, the private key
	# associated with a bitcoin address.
	class UnknownPrivateKey < InvalidAddress
	end

	# UnknownBlock is raised when bitcoind doesn't know about a given block.
	class UnknownBlock < Error
		# This is the block ID that bitcoind didn't know about.
		attr_reader :block_id

		def initialize(block_id)
			@block_id = block_id.freeze
			super("Unknown block ID: #{@block_id.inspect}")
		end
	end

	# UnknownTransaction is raised when bitcoind doesn't know about a given
	# transaction.
	class UnknownTransaction < Error
		# This is the transaction ID that bitcoind didn't know about.
		attr_reader :transaction_id

		def initialize(transaction_id)
			@transaction_id = transaction_id.freeze
			super("Unknown transaction ID: #{@transaction_id.inspect}")
		end
	end

	# InsufficientFunds is raised when an account (or the bitcoind as a whole)
	# doesn't have enough Bitcoin to perform an action.
	class InsufficientFunds < Error
		# This Float is the amount we would need to perform the action.
		attr_reader :required

		# This Float is the actual funds we have available to perform the action.
		attr_reader :available

		def initialize(required, available)
			super("฿#{required} required, but only #{available} available")
		end
	end

	# LockedWallet is raised when bitcoind refuses to send funds because the
	# wallet is locked.
	class LockedWallet < Error
		def initialize()
			super('You must unlock your wallet prior to sending funds.')
		end
	end

	# InvalidPassphrase is raised when we attempt to decrypt the wallet with an
	# invalid passphrase.
	class InvalidPassphrase < Error
		# This is the password we tried (unsuccessfully) to authenticate with.
		attr_reader :bad_password

		def initialize(bad_password)
			@bad_password = bad_password
			super("Invalid password: #{@bad_password.inspect}")
		end
	end

	# This class represents a block in the Bitcoin block chain. (c.f.
	# https://en.bitcoin.it/wiki/Block and
	# https://en.bitcoin.it/wiki/Block_hashing_algorithm)
	class Block
		# This is the Bitcoin::Client instance we are connected to.
		attr_reader :bc

		# This is the unique ID of the block. It is a String beginning with a number
		# of '0's.
		attr_reader :block_id

		# This is the order of this block in the block chain, i.e. the number of
		# blocks that came before it.
		attr_reader :height

		# This is the block version. Currently, it should be +1+.
		attr_reader :version

		# This is a base 16 String representation of a SHA-256 hash generated from
		# all the transactions in the block.
		attr_reader :merkle_root

		# This is a 32-bit Fixnum used in order to get a @block_id matching @target.
		attr_reader :nonce

		# This is a Float representing how difficult it was to generate the block.
		# It increases logarithmically in proportion to difficulty.
		attr_reader :difficulty

		# This is an Array of every Transaction that is part of the block.
		attr_reader :transactions

		# This is a compact representation of the prefix this block was attempting
		# to match.
		attr_reader :target

		# +bc+ is a Bitcoin::Client instance. block_id is our unique (String) block
		# ID. We raise UnknownBitcoinBlock if the bitcoind doesn't know about a
		# block with that ID.
		def initialize(bc, block_id)
			@bc = bc

			unless @bc.is_a?(Bitcoin::Client)
				raise TypeError, "bc must be a Bitcoin::Client (#{@bc.class} given)"
			end

			unless block_id.is_a?(String)
				raise TypeError, "block_id must be a String (#{block_id.class} given)"
			end

			begin
				block_data = @bc.jr.getblock(block_id)
			rescue Jr::ServerError => ex
				if ex.code == -5
					raise UnknownBlock, block_id
				else
					raise
				end
			end

			{
				block_id: :hash,
				height: :height,
				version: :version,
				merkle_root: :merkleroot,
				created_at_unix_time: :time,
				nonce: :nonce,
				difficulty: :difficulty,
				transaction_ids: :tx,
				previous_block_id: :nextblockhash,
				next_block_id: :previoushblockhash
			}.each do |our_attr, block_data_key|
				instance_variable_set(
					"@#{our_attr}",
					block_data[block_data_key.to_s].freeze
				)
			end

			@transactions ||= [].freeze
		end

		# This is the Block created immediately after this one, or +nil+ if this is
		# the most recent block.
		def next_block
			@bc.get_block(@next_block_id)
		end

		# This is the Block created prior to this one, or +nil+ if this is the
		# origin block.
		def previous_block
			@bc.get_block(@previous_block_id)
		end

		# This is the Time the block was created at.
		def created_at
			@created_at ||= Time.at(@created_at_unix_time).utc.freeze
		end

		def inspect
			"#<Bitcoin::Block #{@block_id}>"
		end
	end

	# This represents a single Bitcoin transaction.
	class Transaction
		# This is the Bitcoin::Client instance we're connected to.
		attr_reader :bc

		# This (String) is a unique identifier assigned to this transaction.
		attr_reader :transaction_id

		# This is a Hash whose keys are the (String) bitcoin addresses involved in
		# the transaction (whose private keys bitcoind has) and whose values are the
		# (Float) amounts that the corresponding address gained (in which case the
		# value would be positive) or lost (in which case the value would be
		# negative).
		attr_reader :amounts

		# This is a Hash similar to @amounts, except that the values are the amounts
		# each address paid in transaction fees. (c.f.
		# https://en.bitcoin.it/wiki/Transaction_fees)
		attr_reader :fees

		# +bc+ is a Bitcoin::Client. (The String) +transaction_id+ is our unique
		# transaction ID. If bitcoind doesn't know about a transaction with that ID,
		# we raise UnknownTransaction. Note that bitcoind only knows about
		# transactions involving private keys in our wallet even though information
		# about other transactions is in the block chain.
		def initialize(bc, transaction_id)
			@bc = bc
			@transaction_id = transaction_id.freeze

			unless @bc.is_a?(Bitcoin::Client)
				raise TypeError, "bc must be a Bitcoin::Client (#{@bc.class} given)"
			end

			begin
				info = @bc.jr.gettransaction(transaction_id)
			rescue Jr::ServerError => ex
				if info.code == -5
					raise UnknownTransaction, transaction_id
				end
			end

			@unix_time = info.fetch('time')

			@fees = Hash.new
			@amounts = Hash.new

			info.fetch('details').each do |detail|
				address = detail.fetch('address').freeze

				@amounts[address] = detail.fetch('amount').freeze

				if detail['fee']
					@fees[address] = detail['fee'].freeze
				end
			end

			@fees.freeze
			@amounts.freeze
		end

		# This is the Time the transaction was made.
		def time
			@time ||= Time.at(@unix_time).utc.freeze
		end

		# Does this transaction include +address+? (Note that this only works for
		# addresses which we control.)
		def include?(address)
			address = address.to_s if address.is_a?(Address)
			@fees.keys.include?(address) or @amounts.keys.include?(address)
		end

		def inspect
			"#<Bitcoin::Transaction #{@transaction_id}>"
		end
	end

	# This is a bitcoind account. (c.f.
	# https://en.bitcoin.it/wiki/Accounts_explained)
	class Account
		# This is the Bitcoin::Client instance we are connected to.
		attr_reader :bc

		# This (String) is our account designation.
		attr_reader :name

		# +bc+ is a Bitcoin::Client instance. +account_name+ is the (String) name of
		# the account we're associated with. +account_name+ may be +""+, in which
		# case we represent the default account.
		def initialize(bc, account_name)
			@bc = bc
			@name = account_name.freeze

			unless @name.is_a?(String)
				raise TypeError, "account_name must be a String (#{@name.class} given)"
			end

			unless @bc.is_a?(Bitcoin::Client)
				raise TypeError, "bc must be a Bitcoin::Client (#{@bc.class} given)"
			end
		end

		# Get every Transaction associated with this account.
		def transactions
			grab = 20
			position = 0
			transactions = Array.new

			loop do
				new_transactions = @bc.jr.listtransactions(@name, grab, position)
				transactions += new_transactions.map{|tx| tx.fetch('txid')}

				if new_transactions.length < grab
					break
				else
					position += grab
				end
			end

			transactions.uniq.map do |tx|
				Transaction.new(@bc, tx)
			end
		end

		# Fetch the balance of this account. Only deposits with at least
		# +minimum_confirmations+ will be included in this total.
		def balance(minimum_confirmations=1)
			@bc.jr.getbalance(@name, minimum_confirmations)
		end

		# This is an Array of every Address associated with this account.
		def addresses
			@bc.jr.getaddressesbyaccount(@name).map(&@bc.method(:get_address))
		end

		# Get an unused Address associated with this account, or create one if one
		# doesn't already exist.
		def unused_address
			@bc.get_address(@bc.jr.getaccountaddress(@name))
		end

		# Get a new Address associated with this account.
		def new_address
			@bc.get_address(@bc.jr.getnewaddress(@name))
		end

		# Send +amount+ Bitcoin to +dest+. +amount+ should be a positive real
		# number; +dest+ can either be a (String) bitcoin address, or an Address
		# instance. We return a Transaction.
		def send(dest, amount)
			dest = dest.to_s

			begin
				txid = @bc.jr.sendfrom(@name, dest, amount)
			rescue Jr::ServerError => ex
				case ex.code
					when -13
						raise LockedWallet

					when -6
						raise InsufficientFunds.new(amount, balance)

					when -5
						raise InvalidAddress, dest

					else
						raise
				end
			end

			@bc.get_transaction(txid)
		end

		# +dests+ is a Hash whose keys are Address or String instances and whose
		# values are positive real numbers. Each key is sent the amount of Bitcoin
		# specified by its value. We return a Transaction.
		def send_to_many(dests)
			dests = Hash[
				dests.map do |dest, amount|
					[dest.to_s, amount]
				end
			]

			begin
				txid = @bc.jr.sendmany(@name, dest, amount)
			rescue Jr::ServerError => ex
				case ex.code
					when -13
						raise LockedWallet

					when -6
						raise InsufficientFunds.new(amount.values.reduce(&:+), balance)

					when -5
						raise InvalidAddress, ex.split(':').fetch(1)

					else
						raise
				end
			end

			@bc.get_transaction(txid)
		end

		# Donate +amount+ to katmagic (bc's author).
		def donate(amount)
			tx = send('1LzDffumxiCSh8wEpxWE8fUozb2LUTcL8L', amount)

			if STDOUT.tty?
				puts('katmagic l♥ves y♥u ♥♥dles!')
			end

			tx
		end

		def to_s # :nodoc:
			@name
		end

		def inspect # :nodoc:
			"#<Bitcoin::Account #{@name.inspect}>"
		end
	end

	# This class represents a Bitcoin address.
	class Address
		# This is the Bitcoin::Client instance we are connected to.
		attr_reader :bc

		# This is our actual (String) Bitcoin address.
		attr_reader :address

		# +bc+ is a Bitcoin::Client instance. +address+ is a (String) Bitcoin
		# address that we have the private key for.
		def initialize(bc, address)
			@bc = bc
			@address = address

			unless @bc.is_a?(Bitcoin::Client)
				raise TypeError, "bc must be a Bitcoin::Client (#{@bc.class} given)"
			end

			unless valid?
				raise InvalidAddress, @address
			end
		end

		# Return an Array of every Transaction associated with us.
		def transactions
			account.transactions.find_all do |tx|
				tx.include?(self)
			end
		end

		# Are we a valid Bitcoin address?
		def valid?
			@bc.is_valid?(@address)
		end

		# This is the (String) private key associated with this address. If this
		# account's address is invalid (or from the wrong bitcoin network), we raise
		# InvalidAddress. If we don't have the private key associated with this
		# address (or our wallet is locked), we return +nil+.
		def private_key
			begin
				@private_key ||= @bc.jr.dumpprivkey(@address)
			rescue Jr::ServerError => ex
				$ex = ex.code
				case ex.code
					when -5
						raise(InvalidAddress, @address)
					when -4
						nil
					else
						raise
				end
			end
		end

		# Get the Account we're associated with.
		def account
			@bc.get_account(@bc.jr.getaccount(@address))
		end

		# Associate us with +account+, which can either be a String or an Account.
		# Either way, we will return an Account.
		def account=(account)
			@bc.jr.setaccount(@address, account.to_s)
			@bc.get_account(account.to_s)
		end

		# Sign the (String) message +msg+. We return a detached base-64 encoded
		# signature (String). In order to verify the message, you will need both the
		# signature and +msg+. If we don't know private key, we raise
		# UnknownPrivateKey. (c.f. Client.verify())
		def sign(msg)
			begin
				@bc.jr.signmessage(@address, msg)
			rescue Jr::ServerError => ex
				case ex.code
					when -13
						raise LockedWallet

					when -4
						raise UnknownPrivateKey, @address

					else
						raise
				end
			end
		end

		# Verify the signature +sig+ of a message +msg+ signed by our private key.
		# We return +true+ if the signature is valid, or +false+ if it is not.
		def verify(msg, sig)
			@bc.jr.verifymessage(@address, msg, sig)
		end

		def to_s # :nodoc:
			@address
		end

		def inspect  # :nodoc:
			"#<Bitcoin::Address #{@address}>"
		end
	end

	class Client
		attr_reader :user, :password, :host, :port, :ssl
		# @jr is a Jr::Jr instance connected to the bitcoind.
		attr_reader :jr

		def initialize(user, password, host='127.0.0.1', port=8331, ssl=false)
			%w{user password host port ssl}.each do |var|
				instance_variable_set("@#{var}", eval(var))
			end

			@jr = Jr::Jr.new(@host, @port, @user, @password, ssl)

			@accounts = Hash.new
			@addresses = Hash.new
			@blocks = Hash.new
			@transactions = Hash.new
		end

		# Get an Array of every Address we have.
		def addresses
			@jr.listreceivedbyaddress(0, true).map do |addr_info|
				get_address(addr_info.fetch('address'))
			end
		end

		# Get an Array of every Account we have.
		def accounts
			@jr.listreceivedbyaccount(0, true).map do |acct_info|
				get_account(acct_info.fetch('account'))
			end
		end

		# Get the Address +addr+. If +addr+ is invalid, we raise InvalidAddress. The
		# result of this function is cached.
		def get_address(addr)
			@addresses[addr] ||= Address.new(self, addr)
		end

		# Get the account associated with the String +label+, or create it if it
		# doesn't already exist. The result of this function is cached.
		def get_account(label)
			@accounts[label] ||= Account.new(self, label)
		end
		alias_method :[], :get_account

		# Does +acct+ have any associated addresses?
		def has_account?(acct)
			!get_account(acct).addresses.empty?
		end

		# Get the Block with a hash of +block_id+, or if +block_id+ is a Fixnum, the
		# Block with a height of +block_id+. If +block_id+ is an unknown block ID,
		# we raise UnknownBlock+; if +block_id+ is a Fixnum and there is no
		# associated block, we raise RangeError. The result of this function is
		# cached.
		def get_block(block_id)
			if block_id.is_a?(Fixnum)
				begin
					block_id = @jr.getblockhash(block_id)
				rescue Jr::ServerError => ex
					if ex.code == -1
						raise RangeError, "block_id #{block_id.inspect} is out of range."
					else
						raise
					end
				end
			end

			@blocks[block_id] ||= Block.new(self, block_id)
		end

		# Get the Transaction with the ID +transaction_id+. We raise
		# UnknownTransaction if we don't know about a Transaction with that ID.
		# The result of this function is cached.
		def get_transaction(transaction_id)
			@transactions[transaction_id] ||= Transaction.new(self, transaction_id)
		end

		# Call the (Ruby) block passed for every transaction that has occurred since
		# +block+ (which may be a Block, a block ID, or a block height). We return
		# the last Block processed.
		def each_transactions_since(block)
			unless block.is_a?(Block)
				block = get_block(block)
			end

			info = @jr.listsinceblock(block.block_id)

			txes = info.fetch('transactions')
			txes.map!{ |tx| tx.fetch('txid') }
			txes.uniq!

			txes.each do |txid|
				transaction = get_transaction(txid)
				yield(transaction)
			end

			get_block(info.fetch('lastblock'))
		end

		# Get an Array of every Transaction involving one of our addresses.
		def transactions
			get_transactions_since(0)
		end

		# This is the latest Block we've processed.
		def latest_block
			get_block( @jr.getinfo().fetch('blocks') )
		end

		# Send +amount+ Bitcoin to +dest+. +amount+ should be a positive real
		# number; +dest+ can either be a String bitcoin address, or an Address
		# instance. We return a Transaction.
		def send(dest, amount)
			dest = dest.to_s

			begin
				txid = @jr.sendtoaddress(dest, amount)
			rescue Jr::ServerError => ex
				case ex.code
					when -13
						raise LockedWallet

					when -6
						raise InsufficientFunds.new(amount, balance)

					when -5
						raise InvalidAddress, dest

					else
						raise
				end
			end

			get_transaction(txid)
		end

		# Donate +amount+ to katmagic (bc's author).
		def donate(amount)
			tx = send('1LzDffumxiCSh8wEpxWE8fUozb2LUTcL8L', amount)

			if STDOUT.tty?
				puts('katmagic l♥ves y♥u ♥♥dles!')
			end

			tx
		end

		# Safely copies our wallet to destination at +path+. If +path+ is a
		# directory, we will copy our wallet to +path+/wallet.dat.
		def backup_wallet(path)
			@jr.backupwallet(path)
		end

		# Encrypt the wallet with +passwd+ and stop bitcoind.
		def encrypt_wallet(passwd)
			@jr.encryptwallet(passwd)
		end

		# Change the wallet's passphrase from +old_passwd+ to +new_passwd+.
		def change_wallet_passwd(old_passwd, new_passwd)
			begin
				@jr.walletpassphrasechange(old_passwd, new_passwd)
			rescue Jr::ServerError => ex
				if ex.code == -14
					raise InvalidPassphrase, passwd
				else
					raise
				end
			end
		end

		# Unlock the wallet with +passwd+ for +timeout+ seconds.
		def unlock_wallet(passwd, timeout=300)
			begin
				@jr.walletpassphrase(passwd, timeout)
			rescue Jr::ServerError => ex
				if ex.code == -14
					raise InvalidPassphrase, passwd
				else
					raise
				end
			end
		end

		# Lock the wallet.
		def lock_wallet()
			@jr.walletlock()
		end

		# Get the total balance of all our accounts. (This includes all transactions
		# with at least 1 confirmation.)
		def balance
			@jr.getbalance()
		end

		# How many blocks are there (that we know about) in the block chain?
		def block_count
			@jr.getblockcount()
		end

		# How many peers are we connected to?
		def connection_count
			@jr.getconnectioncount()
		end

		# This is a Float representing the difficulty associated with finding the
		# next block. The higher the number, the more difficult it is. (c.f.
		# https://en.bitcoin.it/wiki/Difficulty)
		def difficulty
			@jr.getdifficulty()
		end

		# Are we trying to generate a block?
		def generate?
			@jr.getgenerate()
		end

		alias_method :generate, :generate?

		# If +should_generate+ is +true+, we instruct bitcoind to begin (or
		# continue) to generate a block. If it is +false+, we do the opposite.
		def generate=(should_generate)
			@jr.setgenerate(should_generate)
			should_generate
		end

		# How many blocks are we hashing per second? This will be zero unless we're
		# trying to generate a block.
		def hashes_per_second
			@jr.gethashespersec()
		end

		# This [Fixnum] is the version of bitcoind we're connecting to.
		def bitcoind_version
			@jr.getinfo().fetch('version')
		end

		# This (Fixnum) is the version of the Bitcoin RPC protocol we're
		# communicating in.
		def protocol_version
			@jr.getinfo().fetch('protocolversion')
		end

		# This is the proxy bitcoind is using, or +nil+ if we're not using a proxy.
		def proxy
			@jr.getinfo().fetch('proxy')
		end

		# Is bitcoind using a proxy?
		def proxy?
			!!proxy
		end

		# Are we on the testnet?
		def testnet?
			@jr.getinfo().fetch('testnet')
		end

		# This is how much we're configured to use as our transaction fee. (c.f.
		# https://en.bitcoin.it/wiki/Transaction_fees)
		def transaction_fee
			@jr.getinfo().fetch('paytxfee')
		end

		# This is the Time the oldest key in our key pool was created. (c.f.
		# key_pool_size())
		def oldest_key
			Time.at(@jr.getinfo().fetch('keypoololdest'))
		end

		# This is the (Fixnum) size of our key pool. The key pool is a pre-generated
		# set of Bitcoin keys which are then allocated through the other address
		# allocation mechanisms. It exists so that backups will (hopefully) contain
		# all the private keys we actually used.
		def key_pool_size
			@jr.getinfo().fetch('keypoolsize')
		end

		# This is a Hash containing data about the next block that will be generated
		# (c.f. the documentation regarding the getmemorypool API call in
		# https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_Calls_list)
		def memory_pool
			@jr.getmemorypool()
		end

		# Import a Bitcoin private key. We will fail if the key already exists in
		# our wallet. We return an Address. (c.f. get_private_key())
		def import_private_key(key, label=nil)
			label ||= ''
			@jr.get_address( @jr.importprivkey(key, label) )
		end

		# Refill our key pool. (c.f. key_pool_size())
		def refill_key_pool()
			@jr.keypoolrefill()
		end

		# Set the transaction fee to +fee+. (c.f.
		# https://en.bitcoin.it/wiki/Transaction_fees)
		def transaction_fee=(fee)
			fee = fee.to_f
			@jr.settxfee(fee)
			fee
		end

		# Stop bitcoind.
		def stop()
			@jr.stop()
		end

		# Is +addr+ a valid bitcoin address? If we're using the testnet, normal
		# addresses won't be valid; if we're not, testnet addresses won't be valid.
		def is_valid?(addr)
			@jr.validateaddress(addr.to_s)['isvalid']
		end
	end
end
