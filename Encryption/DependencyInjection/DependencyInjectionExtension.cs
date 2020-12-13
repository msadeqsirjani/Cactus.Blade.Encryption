using Cactus.Blade.Encryption.Async;
using Cactus.Blade.Guard;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Cactus.Blade.Encryption.DependencyInjection
{
    /// <summary>
    /// Defines extension methods related to dependency injection and encryption.
    /// </summary>
    public static class DependencyInjectionExtension
    {
        /// <summary>
        /// Adds the <see cref="Crypto.Current"/> to the service collection. <see cref="Crypto.Current"/> is
        /// created using configuration or set directly by using <see cref="Crypto.SetCurrent(ICrypto)"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <returns>The same <see cref="IServiceCollection"/>.</returns>
        public static IServiceCollection AddCrypto(this IServiceCollection services)
        {
            Guard.Guard.Against.Null(services, nameof(services));

            services.AddSingleton(_ => Crypto.Current);
            services.AddSingleton(serviceProvider => serviceProvider.GetRequiredService<ICrypto>().AsAsync());

            return services;
        }

        /// <summary>
        /// Adds the specified <see cref="ICrypto"/> to the service collection.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="crypto">The <see cref="ICrypto"/> to add to the service collection.</param>
        /// <returns>The same <see cref="IServiceCollection"/>.</returns>
        public static IServiceCollection AddCrypto(this IServiceCollection services, ICrypto crypto)
        {
            Guard.Guard.Against.Null(services, nameof(services));
            Guard.Guard.Against.Null(crypto, nameof(crypto));

            services.AddSingleton(crypto);
            services.AddSingleton(serviceProvider => serviceProvider.GetRequiredService<ICrypto>().AsAsync());
            return services;
        }

        /// <summary>
        /// Adds the specified <see cref="ICrypto"/> to the service collection.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="cryptoFactory">A func that returns an <see cref="ICrypto"/> when given an <see cref="IServiceProvider"/>.</param>
        /// <returns>The same <see cref="IServiceCollection"/>.</returns>
        public static IServiceCollection AddCrypto(this IServiceCollection services,
            Func<IServiceProvider, ICrypto> cryptoFactory)
        {
            Guard.Guard.Against.Null(services, nameof(services));
            Guard.Guard.Against.Null(cryptoFactory, nameof(cryptoFactory));

            services.AddSingleton(cryptoFactory);
            services.AddSingleton(serviceProvider => serviceProvider.GetRequiredService<ICrypto>().AsAsync());
            return services;
        }
    }
}
