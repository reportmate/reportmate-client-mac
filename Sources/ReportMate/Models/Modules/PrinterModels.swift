import Foundation

/// Printer module data model for macOS - encompasses all printer and print system information
public struct PrinterData: ModuleDataModel, Sendable {
    public var moduleId: String { "printers" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    // Additional printer-specific properties
    public let deviceId: String
    
    // Printer system components
    public let printers: [PrinterInfo]
    public let printQueues: [PrintQueue]
    public let printJobs: [PrintJob]
    public let printDrivers: [PrintDriver]
    public let cupsInfo: CupsInfo
    public let airPrintServices: [AirPrintService]
    
    // Summary statistics
    public let totalPrinters: Int
    public let activePrintJobs: Int
    public let lastPrintActivity: Date?
    
    public init(
        deviceId: String,
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        printers: [PrinterInfo] = [],
        printQueues: [PrintQueue] = [],
        printJobs: [PrintJob] = [],
        printDrivers: [PrintDriver] = [],
        cupsInfo: CupsInfo = CupsInfo(),
        airPrintServices: [AirPrintService] = [],
        totalPrinters: Int = 0,
        activePrintJobs: Int = 0,
        lastPrintActivity: Date? = nil
    ) {
        self.deviceId = deviceId
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.printers = printers
        self.printQueues = printQueues
        self.printJobs = printJobs
        self.printDrivers = printDrivers
        self.cupsInfo = cupsInfo
        self.airPrintServices = airPrintServices
        self.totalPrinters = totalPrinters
        self.activePrintJobs = activePrintJobs
        self.lastPrintActivity = lastPrintActivity
    }
}

/// Printer information structure
public struct PrinterInfo: Codable, Sendable {
    public let name: String
    public let displayName: String
    public let location: String
    public let description: String
    public let make: String
    public let model: String
    public let deviceUri: String
    public let driverName: String
    public let ppd: String? // PostScript Printer Description file
    public let status: String
    public let state: String // idle, processing, stopped
    public let stateMessage: String
    public let stateReasons: [String]
    public let isDefault: Bool
    public let isShared: Bool
    public let isAcceptingJobs: Bool
    public let jobCount: Int
    public let connectionType: String // USB, Network, AirPrint, etc.
    public let ipAddress: String?
    public let macAddress: String?
    public let serial: String?
    public let firmware: String?
    public let supportedMediaTypes: [String]
    public let supportedResolutions: [String]
    public let colorCapable: Bool
    public let duplexCapable: Bool
    public let cupsVersion: String?
    
    public init(
        name: String = "",
        displayName: String = "",
        location: String = "",
        description: String = "",
        make: String = "",
        model: String = "",
        deviceUri: String = "",
        driverName: String = "",
        ppd: String? = nil,
        status: String = "",
        state: String = "",
        stateMessage: String = "",
        stateReasons: [String] = [],
        isDefault: Bool = false,
        isShared: Bool = false,
        isAcceptingJobs: Bool = true,
        jobCount: Int = 0,
        connectionType: String = "",
        ipAddress: String? = nil,
        macAddress: String? = nil,
        serial: String? = nil,
        firmware: String? = nil,
        supportedMediaTypes: [String] = [],
        supportedResolutions: [String] = [],
        colorCapable: Bool = false,
        duplexCapable: Bool = false,
        cupsVersion: String? = nil
    ) {
        self.name = name
        self.displayName = displayName
        self.location = location
        self.description = description
        self.make = make
        self.model = model
        self.deviceUri = deviceUri
        self.driverName = driverName
        self.ppd = ppd
        self.status = status
        self.state = state
        self.stateMessage = stateMessage
        self.stateReasons = stateReasons
        self.isDefault = isDefault
        self.isShared = isShared
        self.isAcceptingJobs = isAcceptingJobs
        self.jobCount = jobCount
        self.connectionType = connectionType
        self.ipAddress = ipAddress
        self.macAddress = macAddress
        self.serial = serial
        self.firmware = firmware
        self.supportedMediaTypes = supportedMediaTypes
        self.supportedResolutions = supportedResolutions
        self.colorCapable = colorCapable
        self.duplexCapable = duplexCapable
        self.cupsVersion = cupsVersion
    }
}

/// Print queue information
public struct PrintQueue: Codable, Sendable {
    public let name: String
    public let printerName: String
    public let jobCount: Int
    public let status: String
    public let state: String
    public let isPaused: Bool
    public let isProcessing: Bool
    public let hasJobs: Bool
    public let jobs: [PrintJob]
    
    public init(
        name: String = "",
        printerName: String = "",
        jobCount: Int = 0,
        status: String = "",
        state: String = "",
        isPaused: Bool = false,
        isProcessing: Bool = false,
        hasJobs: Bool = false,
        jobs: [PrintJob] = []
    ) {
        self.name = name
        self.printerName = printerName
        self.jobCount = jobCount
        self.status = status
        self.state = state
        self.isPaused = isPaused
        self.isProcessing = isProcessing
        self.hasJobs = hasJobs
        self.jobs = jobs
    }
}

/// Print job information
public struct PrintJob: Codable, Sendable {
    public let id: Int
    public let name: String
    public let user: String
    public let printer: String
    public let status: String
    public let priority: Int
    public let size: Int // in bytes
    public let pages: Int
    public let completedPages: Int
    public let submissionTime: Date
    public let processTime: Date?
    public let completionTime: Date?
    public let format: String // PDF, PostScript, etc.
    
    public init(
        id: Int = 0,
        name: String = "",
        user: String = "",
        printer: String = "",
        status: String = "",
        priority: Int = 0,
        size: Int = 0,
        pages: Int = 0,
        completedPages: Int = 0,
        submissionTime: Date = Date(),
        processTime: Date? = nil,
        completionTime: Date? = nil,
        format: String = ""
    ) {
        self.id = id
        self.name = name
        self.user = user
        self.printer = printer
        self.status = status
        self.priority = priority
        self.size = size
        self.pages = pages
        self.completedPages = completedPages
        self.submissionTime = submissionTime
        self.processTime = processTime
        self.completionTime = completionTime
        self.format = format
    }
}

/// Print driver information
public struct PrintDriver: Codable, Sendable {
    public let name: String
    public let version: String
    public let vendor: String
    public let modelSupported: String
    public let language: String // PostScript, PCL, etc.
    public let ppdFile: String?
    public let filterPath: String?
    public let installDate: Date?
    public let isSystemDriver: Bool
    public let supportedFeatures: [String]
    
    public init(
        name: String = "",
        version: String = "",
        vendor: String = "",
        modelSupported: String = "",
        language: String = "",
        ppdFile: String? = nil,
        filterPath: String? = nil,
        installDate: Date? = nil,
        isSystemDriver: Bool = false,
        supportedFeatures: [String] = []
    ) {
        self.name = name
        self.version = version
        self.vendor = vendor
        self.modelSupported = modelSupported
        self.language = language
        self.ppdFile = ppdFile
        self.filterPath = filterPath
        self.installDate = installDate
        self.isSystemDriver = isSystemDriver
        self.supportedFeatures = supportedFeatures
    }
}

/// CUPS system information
public struct CupsInfo: Codable, Sendable {
    public let version: String
    public let serverName: String
    public let serverVersion: String
    public let isRunning: Bool
    public let configFile: String
    public let logFile: String
    public let errorLogFile: String
    public let accessLogFile: String
    public let pageLogFile: String
    public let serverRoot: String
    public let dataDir: String
    public let documentRoot: String
    public let requestRoot: String
    public let tempDir: String
    public let maxJobs: Int
    public let maxJobsPerUser: Int
    public let maxJobsPerPrinter: Int
    public let jobRetryLimit: Int
    public let jobRetryInterval: Int
    
    public init(
        version: String = "",
        serverName: String = "",
        serverVersion: String = "",
        isRunning: Bool = false,
        configFile: String = "/etc/cups/cupsd.conf",
        logFile: String = "/var/log/cups/error_log",
        errorLogFile: String = "/var/log/cups/error_log",
        accessLogFile: String = "/var/log/cups/access_log",
        pageLogFile: String = "/var/log/cups/page_log",
        serverRoot: String = "/etc/cups",
        dataDir: String = "/usr/share/cups",
        documentRoot: String = "/usr/share/doc/cups",
        requestRoot: String = "/var/spool/cups",
        tempDir: String = "/var/spool/cups/tmp",
        maxJobs: Int = 0,
        maxJobsPerUser: Int = 0,
        maxJobsPerPrinter: Int = 0,
        jobRetryLimit: Int = 5,
        jobRetryInterval: Int = 300
    ) {
        self.version = version
        self.serverName = serverName
        self.serverVersion = serverVersion
        self.isRunning = isRunning
        self.configFile = configFile
        self.logFile = logFile
        self.errorLogFile = errorLogFile
        self.accessLogFile = accessLogFile
        self.pageLogFile = pageLogFile
        self.serverRoot = serverRoot
        self.dataDir = dataDir
        self.documentRoot = documentRoot
        self.requestRoot = requestRoot
        self.tempDir = tempDir
        self.maxJobs = maxJobs
        self.maxJobsPerUser = maxJobsPerUser
        self.maxJobsPerPrinter = maxJobsPerPrinter
        self.jobRetryLimit = jobRetryLimit
        self.jobRetryInterval = jobRetryInterval
    }
}

/// AirPrint service information
public struct AirPrintService: Codable, Sendable {
    public let serviceName: String
    public let hostName: String
    public let port: Int
    public let ipAddress: String
    public let make: String
    public let model: String
    public let features: [String]
    public let pdl: [String] // Page Description Languages
    public let colorSupported: Bool
    public let duplexSupported: Bool
    public let txtRecord: [String: String] // DNS-SD TXT record
    
    public init(
        serviceName: String = "",
        hostName: String = "",
        port: Int = 631,
        ipAddress: String = "",
        make: String = "",
        model: String = "",
        features: [String] = [],
        pdl: [String] = [],
        colorSupported: Bool = false,
        duplexSupported: Bool = false,
        txtRecord: [String: String] = [:]
    ) {
        self.serviceName = serviceName
        self.hostName = hostName
        self.port = port
        self.ipAddress = ipAddress
        self.make = make
        self.model = model
        self.features = features
        self.pdl = pdl
        self.colorSupported = colorSupported
        self.duplexSupported = duplexSupported
        self.txtRecord = txtRecord
    }
}