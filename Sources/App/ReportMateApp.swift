import SwiftUI

@main
struct ReportMateApp: App {
    @State private var xpcClient = XPCClient()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(xpcClient)
                .frame(minWidth: 700, minHeight: 500)
                .onAppear {
                    xpcClient.setup()
                }
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 850, height: 748)
    }
}
