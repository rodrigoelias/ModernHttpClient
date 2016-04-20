using Java.Net;
using Java.Security;
using Java.Security.Cert;
using Javax.Net.Ssl;
using Square.OkHttp;
using Java.Interop;

namespace ModernHttpClient.Unsecure
{    // Usage:
    //
    // // if we want to use the defaults
    // SSLManager.SetupDefault()
    //
    // // if we want to use the client with certificate from an unknown CA
    // SSLManager.SetupUnknownAuthority()
    //
    // // if we want to use the client with our self-signed certificate
    // SSLManager.SetupSelfSigned()
    //
    // // if we want to use the allow-all client
    // SSLManager.SetupDangerous()
    //
    // // now we get the client
    // var client = SSLManager.GetHttpClient();
    //
    public static class SSLManager
    {
        private static IHostnameVerifier hostnameVerifier;
        private static SSLSocketFactory socketFactory;

        /// <summary>
        /// Setups the default socket factory using the system certificates
        /// </summary>
        public static void SetupDefault()
        {
            // apply the default context
            Setup(HttpsURLConnection.DefaultSSLSocketFactory, null);
        }


        /// <summary>
        /// Sets up the socket factory and hostname verifier to allow all 
        /// certificates for all servers.
        /// </summary>
        public static void SetupDangerous()
        {
            // we want to use a new trust manager (high risk!)
            var context = SSLContext.GetInstance("TLSv1.2");
            context.Init(null, new ITrustManager[] { new NullX509TrustManager() }, new SecureRandom());

            // apply the new context
            Setup(context.SocketFactory, new NullHostnameVerifier());
        }

        /// <summary>
        /// Sets up the socket factory and the hostname verifier for the next time a 
        /// client is requested.
        /// </summary>
        private static void Setup(SSLSocketFactory factory, IHostnameVerifier verifier)
        {
            // create our custom socket factory to handle TLS v1.2 on older devices
            // although we can actually use it on any Android version as it is just 
            // a proxy class that makes sure all supported protocols are enabled
            //if (Android.OS.Build.VERSION.SdkInt < BuildVersionCodes.Lollipop)
            //{
            socketFactory = new CompleteSSLSocketFactory(factory);
            //}
            //else
            //{
            //    socketFactory = factory;
            //}

            // set the hostname verifer
            hostnameVerifier = verifier;
        }

        /// <summary>
        /// Provides an OkHttpClient that is set up with the requested 
        /// socket factory and hostname provider (if any).
        /// </summary>
        public static OkHttpClient GetHttpClient()
        {
            SetupDangerous();
            // create a new client
            var client = new OkHttpClient();
            // add the socket factory
            client.SetSslSocketFactory(socketFactory);
            // make sure we use the hostname verifier
            if (hostnameVerifier != null)
            {
                client.SetHostnameVerifier(hostnameVerifier);
            }
            return client;
        }

        private class CompleteSSLSocketFactory : SSLSocketFactory
        {
            private readonly SSLSocketFactory innerFactory;

            public CompleteSSLSocketFactory(SSLSocketFactory innerFactory)
            {
                this.innerFactory = innerFactory;
            }

            public override string[] GetDefaultCipherSuites()
            {
                return innerFactory.GetDefaultCipherSuites();
            }

            public override string[] GetSupportedCipherSuites()
            {
                return innerFactory.GetSupportedCipherSuites();
            }

            public override Socket CreateSocket()
            {
                return MakeSocketSafe(innerFactory.CreateSocket());
            }

            public override Socket CreateSocket(Socket s, string host, int port, bool autoClose)
            {
                return MakeSocketSafe(innerFactory.CreateSocket(s, host, port, autoClose));
            }

            public override Socket CreateSocket(string host, int port)
            {
                return MakeSocketSafe(innerFactory.CreateSocket(host, port));
            }

            public override Socket CreateSocket(string host, int port, InetAddress localHost, int localPort)
            {
                return MakeSocketSafe(innerFactory.CreateSocket(host, port, localHost, localPort));
            }

            public override Socket CreateSocket(InetAddress host, int port)
            {
                return MakeSocketSafe(innerFactory.CreateSocket(host, port));
            }

            public override Socket CreateSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            {
                return MakeSocketSafe(innerFactory.CreateSocket(address, port, localAddress, localPort));
            }

            private Socket MakeSocketSafe(Socket socket)
            {
                var sslSocket = socket as SSLSocket;
                if (sslSocket != null)
                {
                    // enable all supported protocols for this socket
                    sslSocket.SetEnabledProtocols(sslSocket.GetSupportedProtocols());
                    sslSocket.SetEnabledCipherSuites(sslSocket.GetSupportedCipherSuites());
                }
                return socket;
            }
        }


        /// <summary>
        /// This trust manager wraps a custom socket factory and provides a 
        /// fallback to the default trust manager with the system certificates.
        /// This allows the app to communicate not only with a self-signed 
        /// server, but also servers with certificates from a CA.
        /// </summary>
        private class CompleteX509TrustManager : Java.Lang.Object, IX509TrustManager
        {
            private readonly IX509TrustManager defaultTrustManager;
            private readonly IX509TrustManager localTrustManager;

            public CompleteX509TrustManager(IX509TrustManager localTrustManager)
            {
                this.localTrustManager = localTrustManager;

                var defaultTrustManagerFactory = TrustManagerFactory.GetInstance(TrustManagerFactory.DefaultAlgorithm);
                defaultTrustManagerFactory.Init((KeyStore)null);
                defaultTrustManager = defaultTrustManagerFactory.GetTrustManagers()[0].JavaCast<IX509TrustManager>();
            }

            public void CheckClientTrusted(X509Certificate[] chain, string authType)
            {
                // we are the client
            }

            public void CheckServerTrusted(X509Certificate[] chain, string authType)
            {
                try
                {
                    defaultTrustManager.CheckServerTrusted(chain, authType);
                }
                catch (CertificateException)
                {
                    localTrustManager.CheckServerTrusted(chain, authType);
                }
            }

            public X509Certificate[] GetAcceptedIssuers()
            {
                // we are not the server
                return null;
            }
        }


        /// <summary>
        /// This trust manager treats all certificates as valid, without doing 
        /// any checks.
        /// </summary>
        private class NullX509TrustManager : Java.Lang.Object, IX509TrustManager
        {
            public void CheckClientTrusted(X509Certificate[] chain, string authType)
            {
                // we are the client
            }

            public void CheckServerTrusted(X509Certificate[] chain, string authType)
            {
                // don't do any verification
                // all certificates are valid
            }

            public X509Certificate[] GetAcceptedIssuers()
            {
                // we are not the server
                return null;
            }
        }


        /// <summary>
        /// This hostname verifier permits all host names to accessed, even if 
        /// there is no valid certificate for it.
        /// </summary>
        private class NullHostnameVerifier : Java.Lang.Object, IHostnameVerifier
        {
            public bool Verify(string hostname, ISSLSession session)
            {
                // everything goes through
                // all host names are valid
                return true;
            }
        }
    }
}