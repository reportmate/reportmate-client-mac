import ReportMate

/// Standalone collector binary, for running outside the app bundle.
@main
enum Runner {
    static func main() async {
        await ReportMateClient.main()
    }
}
