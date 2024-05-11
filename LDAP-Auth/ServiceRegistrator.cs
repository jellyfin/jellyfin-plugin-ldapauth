using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.LDAP_Auth;

/// <summary>
/// Register LDAP services.
/// </summary>
public class ServiceRegistrator : IPluginServiceRegistrator
{
    /// <inheritdoc />
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<IAuthenticationProvider, LdapAuthenticationProviderPlugin>();
        serviceCollection.AddSingleton<IPasswordResetProvider, LdapAuthenticationProviderPlugin>();
    }
}
