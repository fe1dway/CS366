using System.CommandLine;

internal class Program {
    private static async Task<int> Main(string[] args) {
        var rootCommand = new RootCommand("Runs an echo server or client");

        // Command line arguments
        var portOption = new Option<ushort>("--port") {
            Description = "The port to connect to.",
            DefaultValueFactory = _ => 4000
        };

        var addressOption = new Option<string>("--address") {
            Description = "The address to connect to",
            DefaultValueFactory = _ => "localhost"
        };

        // Setup the client command
        var clientCommand = new Command("client", "Start an echo client") {
            portOption,
            addressOption
        };
        rootCommand.Subcommands.Add(clientCommand);

        clientCommand.SetAction(async parseResult =>
            await new EncryptedEchoClient(parseResult.GetValue(portOption), parseResult.GetValue(addressOption)!).Run()
        );

        // Setup the server command
        var serverCommand = new Command("server", "Start an echo server") {
            portOption
        };
        rootCommand.Subcommands.Add(serverCommand);

        serverCommand.SetAction(async parseResult => await new EncryptedEchoServer(parseResult.GetValue(portOption)).Run());

        return await rootCommand.Parse(args).InvokeAsync();
    }
}