using System;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Serialization;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

namespace Jellyfin.Plugin.LDAP_Auth
{
    public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
    {
        public static Plugin Instance { get; private set; }
        public static ILogger Logger{get; private set;}
        public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer, ILogger logger) : base(applicationPaths, xmlSerializer){
            Instance = this;
            Logger = logger;
        }

        public override string Name => "LDAP-Auth";
        public override Guid Id => Guid.Parse("958aad66-3784-4d2a-b89a-a7b6fab6e25c");

        public IEnumerable<PluginPageInfo> GetPages()
        {
            return new[]
            {
                new PluginPageInfo
                {
                    Name = this.Name,
                    EmbeddedResourcePath = $"{GetType().Namespace}.Config.configPage.html"
                }
            };
        }
    }
}
