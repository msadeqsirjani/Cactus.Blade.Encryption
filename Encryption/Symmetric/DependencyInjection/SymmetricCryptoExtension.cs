using Cactus.Blade.Guard;
using Microsoft.Extensions.DependencyInjection;

namespace Cactus.Blade.Encryption.Symmetric.DependencyInjection
{
    /// <summary>
    /// Defines extension methods for
    /// injection with <see cref="SymmetricCrypto"/>.
    /// </summary>
    public static class SymmetricCryptoExtension
    {
        private const ServiceLifetime DefaultLifetime = ServiceLifetime.Singleton;

        /// <summary>
        /// Adds a <see cref="SymmetricCrypto"/> to the service collection.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="lifetime">The <see cref="ServiceLifetime"/>.</param>
        /// <returns></returns>
        public static SymmetricCryptoBuilder AddSymmetricCrypto(this IServiceCollection services,
            ServiceLifetime lifetime = DefaultLifetime)
        {
            Guard.Guard.Against.Null(services, nameof(services));

            var builder = new SymmetricCryptoBuilder();

            services.Add(new ServiceDescriptor(typeof(ICrypto), builder.Build, lifetime));

            return builder;
        }
    }
}
