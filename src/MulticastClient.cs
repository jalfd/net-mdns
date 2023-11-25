using Common.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Makaretu.Dns
{
    /// <summary>
    ///   Performs the magic to send and receive datagrams over multicast
    ///   sockets.
    /// </summary>
    internal class MulticastClient : IDisposable
    {
        private static readonly ILog Logger = LogManager.GetLogger<MulticastClient>();

        /// <summary>
        ///   The port number assigned to Multicast DNS.
        /// </summary>
        /// <value>
        ///   Port number 5353.
        /// </value>
        public static readonly int MulticastPort = 5353;

        private static readonly IPAddress MulticastAddressIPv4 = IPAddress.Parse("224.0.0.251");

        private readonly List<UdpClient> _receivers = [];
        private readonly ConcurrentDictionary<IPAddressAndNIC, UdpClient> _senders = new();
        private readonly Func<IPAddress, IPv6MulticastAddressScope> _ipv6MulticastScopeSelector;

        private bool _isDisposed = false;

        public event EventHandler<UdpReceiveResult> MessageReceived;

        public MulticastClient(bool useIPv4, bool useIpv6, IEnumerable<NetworkInterface> nics, Func<IPAddress, IPv6MulticastAddressScope> ipv6MulticastScopeSelector)
        {
            _ipv6MulticastScopeSelector = ipv6MulticastScopeSelector;

            // Setup the receivers.
            UdpClient receiver4 = null;
            if (useIPv4)
            {
                receiver4 = new UdpClient(AddressFamily.InterNetwork);
                receiver4.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                receiver4.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, 255);
                receiver4.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
                receiver4.Client.Bind(new IPEndPoint(IPAddress.Any, MulticastPort));
                _receivers.Add(receiver4);
            }

            UdpClient receiver6 = null;
            if (useIpv6)
            {
                receiver6 = new UdpClient(AddressFamily.InterNetworkV6);
                receiver6.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                receiver6.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IpTimeToLive, 255);
                receiver6.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                receiver6.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, MulticastPort));
                _receivers.Add(receiver6);
            }

            // Get the IP addresses that we should send to.
            var addressesAndNics = nics
                .SelectMany(GetNetworkInterfaceLocalAddresses)
                .Where(a => (useIPv4 && a.Address.AddressFamily == AddressFamily.InterNetwork)
                    || (useIpv6 && a.Address.AddressFamily == AddressFamily.InterNetworkV6));
            foreach (var addressAndNic in addressesAndNics)
            {
                if (_senders.ContainsKey(addressAndNic))
                {
                    continue;
                }
                var address = addressAndNic.Address;

                var localEndpoint = new IPEndPoint(address, MulticastPort);
                var sender = new UdpClient(address.AddressFamily);
                try
                {
                    switch (address.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            var mcastOption4 = new MulticastOption(MulticastAddressIPv4, address);
                            receiver4?.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, mcastOption4);
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, 255);
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, mcastOption4);
                            break;

                        case AddressFamily.InterNetworkV6:
                            var mcastOption6 = new IPv6MulticastOption(GetMulticastAddressIPv6(address), address.ScopeId);
                            receiver6?.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, mcastOption6);
                            sender.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IpTimeToLive, 255);
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                            sender.Client.Bind(localEndpoint);
                            sender.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, mcastOption6);
                            break;

                        default:
                            throw new NotSupportedException($"Address family {address.AddressFamily}.");
                    }

                    _receivers.Add(sender);
                    Logger.Debug($"Will send via {localEndpoint}");
                    if (!_senders.TryAdd(addressAndNic, sender)) // Should not fail
                    {
                        sender.Dispose();
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressNotAvailable)
                {
                    // VPN NetworkInterfaces
                    sender.Dispose();
                }
                catch (Exception e)
                {
                    Logger.Error($"Cannot setup send socket for {address}: {e.Message}", e);
                    sender.Dispose();
                }
            }

            // Start listening for messages.
            foreach (var r in _receivers)
            {
                Listen(r);
            }
        }

        /// <summary>
        /// Send a multicast message
        /// </summary>
        /// <param name="message">The message itself</param>
        /// <param name="filterOnInterface">Toggle if address records should be filtered to contain only those valid on the network interface</param>
        /// <returns></returns>
        public async Task SendAsync(Message message, bool filterOnInterface)
        {
            foreach (var sender in _senders)
            {
                try
                {
                    var multicastAddress = sender.Key.Address.AddressFamily == AddressFamily.InterNetwork
                        ? MulticastAddressIPv4
                        : GetMulticastAddressIPv6(sender.Key.Address);

                    var actualMessage = filterOnInterface ? GetFilteredMessage(message, sender.Key.Interface) : message.ToByteArray();

                    await sender.Value.SendAsync(actualMessage, actualMessage.Length, new(multicastAddress, MulticastPort)).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    Logger.Error($"Sender {sender.Key} failure: {e.Message}");
                    // eat it.
                }
            }
        }

        /// <summary>
        /// Send a unicast message
        /// </summary>
        /// <param name="nic">The network interface on which to send (used for filtering address records in the message)</param>
        /// <param name="unicastClient">The client to use for sending the message</param>
        /// <param name="remote">The recipient of the message</param>
        /// <param name="message">The message itself</param>
        /// <param name="filterOnInterface">Toggle if address records should be filtered to contain only those valid on the network interface</param>
        /// <returns></returns>
        public async Task SendAsUnicastAsync(NetworkInterface nic, UdpClient unicastClient, IPEndPoint remote, Message message, bool filterOnInterface)
        {
            var actualPacket = nic != null ? GetFilteredMessage(message, nic) : message.ToByteArray();
            await unicastClient!.SendAsync(actualPacket, actualPacket.Length, remote).ConfigureAwait(false);
        }

        /// <summary>
        /// Filters <see cref="AddressRecord"/> entries in a Message, removing any that are not valid on the specified interface
        /// </summary>
        /// <param name="msg">The message to filter</param>
        /// <param name="networkInterface">The network interface on which addresses must be valid</param>
        /// <returns>The serialized message</returns>
        private static byte[] GetFilteredMessage(Message msg, NetworkInterface networkInterface)
        {
            // Make a backup of the properties we're going to change
            var originalAllAdditional = msg.AdditionalRecords.ToList();
            var originalAllAnswers = msg.Answers.ToList();

            try
            {
                var nicAddresses = networkInterface.GetIPProperties().UnicastAddresses.Select(a => a.Address).ToList();
                msg.AdditionalRecords.RemoveAll(record =>
                    record is AddressRecord addressRecord && !nicAddresses.Contains(addressRecord.Address));
                msg.Answers.RemoveAll(record =>
                    record is AddressRecord addressRecord && !nicAddresses.Contains(addressRecord.Address));
                return msg.ToByteArray();
            }
            finally
            {
                // Restore msg to its initial state, since multicast response depends on being able to reuse it
                msg.AdditionalRecords = originalAllAdditional;
                msg.Answers = originalAllAnswers;
            }
        }

        private void Listen(UdpClient receiver)
        {
            // ReceiveAsync does not support cancellation.  So the receiver is disposed
            // to stop it. See https://github.com/dotnet/corefx/issues/9848
            Task.Run(async () =>
            {
                try
                {
                    var task = receiver.ReceiveAsync();

                    _ = task.ContinueWith(x => Listen(receiver), TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.RunContinuationsAsynchronously);

                    _ = task.ContinueWith(x => MessageReceived?.Invoke(this, x.Result), TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.RunContinuationsAsynchronously);

                    await task.ConfigureAwait(false);
                }
                catch
                {
                    // Ignore
                }
            });
        }

        private IEnumerable<IPAddressAndNIC> GetNetworkInterfaceLocalAddresses(NetworkInterface nic)
        {
            return nic
                .GetIPProperties()
                .UnicastAddresses
                .Select(x => new IPAddressAndNIC { Address = x.Address, Interface = nic })
                .Where(x => x.Address.AddressFamily != AddressFamily.InterNetworkV6 || x.Address.IsIPv6LinkLocal);
        }

        private IPAddress GetMulticastAddressIPv6(IPAddress localAddress)
        {
            return IPAddress.Parse($"FF0{(byte)_ipv6MulticastScopeSelector(localAddress):X1}::FB");
        }

        #region IDisposable Support

        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    MessageReceived = null;

                    foreach (var receiver in _receivers)
                    {
                        try
                        {
                            receiver.Dispose();
                        }
                        catch
                        {
                            // eat it.
                        }
                    }
                    _receivers.Clear();
                    _senders.Clear();
                }

                _isDisposed = true;
            }
        }

        ~MulticastClient()
        {
            Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion IDisposable Support

        private class IPAddressAndNIC
        {
            public IPAddress Address { get; set; }

            public NetworkInterface Interface { get; set; }

            // override object.Equals
            public override bool Equals(object obj)
            {
                if (obj == null || GetType() != obj.GetType())
                {
                    return false;
                }

                var other = obj as IPAddressAndNIC;

                if (!Equals(other.Address)) { return false; }

                return Interface.Id.Equals(other.Interface.Id);
            }

            public override int GetHashCode()
            {
                // .net framework doesn't have HashCode.Combine :(
                // Use the recommended alternative from https://stackoverflow.com/a/263416

                var hash = 17;
                hash *= 23 + Address.GetHashCode();
                hash *= 23 + Interface.Id.GetHashCode();
                return hash;
            }
        }
    }
}
