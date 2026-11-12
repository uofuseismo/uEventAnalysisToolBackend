#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <stdlib.h>
#include <string>
#include <thread>
#include <utility>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <grpcpp/impl/service_type.h>
#include <sodium/core.h>
#include "uEventAnalysisToolBackend/version.hpp"
#include "programOptions.hpp"
#include "parseCommandLineOptions.hpp"
#include "logger.hpp"

#include "uEventAnalysisToolBackend/auth/administratorLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/userAdministration.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
//#include "uEventAnalysisToolBackend/database/credentials.hpp"
#include "uEventAnalysisToolBackend/grpc/server.hpp"

#include "uEventAnalysisToolBackend/services/authService.hpp"
#include "uEventAnalysisToolBackend/services/adminService.hpp"
/*
#include "uEventAnalysisToolBackend/database/aqms/aqms.hpp"

#include "uEventAnalysisToolBackend/database/aqms/event.hpp"
*/

namespace
{

volatile std::sig_atomic_t mSignalStatus;
std::atomic_bool mInterrupted{false};

/// Token verifier options are tightly coupled to the login authority since it
/// is the token generator.
UEventAnalysisToolBackend::Auth::TokenVerifierOptions
fromLoginAuthorityOptions(
    const UEventAnalysisToolBackend::Auth::AdministratorLoginAuthorityOptions &loginOptions,
    const std::chrono::seconds &leeway)
{
    using namespace UEventAnalysisToolBackend::Auth;
    TokenVerifierOptions result;
    const auto publicPrivateKey = loginOptions.getKeyPair();
    if (loginOptions.getAlgorithm() !=
        AdministratorLoginAuthorityOptions::Algorithm::EdDSA25519)
    {
        throw std::runtime_error("Only eddsa25519 supported");
    }
    result.setPublicKeyAndAlgorithm(
        publicPrivateKey.first, 
        TokenVerifierOptions::Algorithm::EdDSA25519);
    result.setIssuer(loginOptions.getIssuer());
    result.setClockLeeway(leeway); 
    return result;
}

UEventAnalysisToolBackend::Auth::TokenVerifierOptions
fromLoginAuthorityOptions(
    const UEventAnalysisToolBackend::Auth::UserLoginAuthorityOptions &loginOptions,
    const std::chrono::seconds &leeway)
{
    using namespace UEventAnalysisToolBackend::Auth;
    TokenVerifierOptions result;
    const auto publicPrivateKey = loginOptions.getKeyPair();
    if (loginOptions.getAlgorithm() !=
        UserLoginAuthorityOptions::Algorithm::EdDSA25519)
    {   
        throw std::runtime_error("Only eddsa25519 supported");
    }   
    result.setPublicKeyAndAlgorithm(
        publicPrivateKey.first, 
        TokenVerifierOptions::Algorithm::EdDSA25519);
    result.setIssuer(loginOptions.getIssuer());
    result.setClockLeeway(leeway); 
    return result;
}


}

class Process
{
public:
    Process(::ProgramOptions &programOptions,
            std::shared_ptr<spdlog::logger> logger) :
        mOptions(std::move(programOptions)),
        mLogger(std::move(logger))
    {
        namespace UEAT = UEventAnalysisToolBackend;
        if (mLogger == nullptr)
        {
            throw std::invalid_argument("Application logger is null");
        }

        // Admin auth
        auto adminTokenVerifierOptions
            = ::fromLoginAuthorityOptions(
                mOptions.adminLoginAuthorityOptions,
                std::chrono::seconds {0});
        mAdministratorLoginAuthority
            = std::make_shared<UEAT::Auth::AdministratorLoginAuthority> (
                mOptions.adminLoginAuthorityOptions,
                mLogger); 
        mAdministratorTokenVerifier
            = std::make_shared<UEAT::Auth::AdministratorTokenVerifier>
              (adminTokenVerifierOptions, mLogger);

        // User auth
        auto userTokenVerifierOptions
            = ::fromLoginAuthorityOptions(
                mOptions.userLoginAuthorityOptions,
                std::chrono::seconds {0});
        mUserTokenVerifier
            = std::make_shared<UEAT::Auth::UserTokenVerifier>
              (userTokenVerifierOptions, mLogger);
        mUserLoginAuthority
            = std::make_shared<UEAT::Auth::UserLoginAuthority> (
                mOptions.userLoginAuthorityOptions,
                mLogger);

        mUserAdministration
            = std::make_shared<UEAT::Auth::UserAdministration> (
                 mOptions.userAdminOptions,
                 mLogger);

        // Create the services
        std::map<std::string, std::unique_ptr<grpc::Service>> servicesMap;

        std::unique_ptr<grpc::Service> authService
            = std::make_unique<UEAT::Services::AuthService>
              (mUserLoginAuthority,
               mUserTokenVerifier,
               mLogger); 
        servicesMap.insert(std::pair {"AuthService", std::move(authService)});

        std::unique_ptr<grpc::Service> adminService
            = std::make_unique<UEAT::Services::AdminService>
              (mAdministratorLoginAuthority,
               mAdministratorTokenVerifier,
               mUserAdministration,
               mUserTokenVerifier,
               mLogger); 
        servicesMap.insert(std::pair {"AdminService", std::move(adminService)});


        mServer
            = std::make_unique<UEAT::GRPC::Server> 
              (
                mOptions.grpcServerOptions,
                std::move(servicesMap),
                mLogger
              );

    }

    /// Destructor
    ~Process()
    {
        stop();
    }

    /// @brief Starts the application
    void start()
    {
        mKeepRunning.store(true);

        mIsRunning = true;

        auto serviceFuture = mServer->start();
        mFuturesMap.insert_or_assign("gRPCService", std::move(serviceFuture));

        handleMainThread();
    }

    /// @brief Stop the application
    void stop()
    {
        // Help my cleaning thread out
/*
        mTerminateRequested = true;
        mTerminateCondition.notify_all();
*/

        if (mIsRunning)
        {
            mIsRunning = false;

            if (mServer != nullptr)
            {
                mServer->stop();
                std::this_thread::sleep_for(std::chrono::milliseconds {15});
            }
        }

        for (auto &futurePair : mFuturesMap) 
        {
            if (futurePair.second.valid()){futurePair.second.get();}
        }
    }

    /// @brief Periodically prints a summary to a log file as another way
    ///        to demonstrate this application is alive and doing what it is
    ///        supposed to.
    void printSummary()
    {   
        /// Summary 
        if (mOptions.printSummaryInterval.count() <= 0){return;}
        const auto now = 
            std::chrono::duration_cast<std::chrono::seconds>
            ((std::chrono::high_resolution_clock::now()).time_since_epoch());
        if (now < mLastReport + mOptions.printSummaryInterval){return;}
        mLastReport = now;
    }

    /// @brief Checks for errors on the threads.
    /// @result True indicates everything appears okay.
    [[nodiscard]] bool checkFuturesOkay(
        const std::chrono::milliseconds &waitForFuture)
    {
        bool isOkay{true};
        return isOkay;
    }
 
    /// @brief Handles main thread activities.
    void handleMainThread()
    {   
        SPDLOG_LOGGER_INFO(mLogger, "Main thread entering waiting loop");
        stdCatchSignals();
        while (!mStopRequested)
        {
            if (mInterrupted)
            {
                SPDLOG_LOGGER_INFO(mLogger,
                                   "SIGINT/SIGTERM signal received!");
                mStopRequested = true;
                break;
            }
            constexpr std::chrono::milliseconds waitForFuture {5};
            if (!checkFuturesOkay(waitForFuture))
            {
                SPDLOG_LOGGER_CRITICAL(mLogger,
                   "Futures exception caught; terminating app");
                mStopRequested = true;
                break;
            }
            printSummary();
            std::unique_lock<std::mutex> lock(mStopMutex);
            constexpr std::chrono::milliseconds pause{100};
            mStopCondition.wait_for(lock, pause,
                                    [this]
                                    {
                                        return mStopRequested;
                                    });
        }
        if (mStopRequested)
        {
            SPDLOG_LOGGER_DEBUG(mLogger,
                                "Stop request received.  Terminating...");
            stop();
            std::this_thread::sleep_for(std::chrono::milliseconds {15});
        }
    }   
 
    void stdCatchSignals()
    {   
        std::signal(SIGINT,  Process::stdSignalHandler);
        std::signal(SIGTERM, Process::stdSignalHandler);
    }   

    static void stdSignalHandler(const int signal)
    {
        mSignalStatus = signal;
        mInterrupted.store(true);
    }   

    Process() = delete;
//private:
    ::ProgramOptions mOptions;
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    std::shared_ptr<UEventAnalysisToolBackend::Auth::AdministratorLoginAuthority>
        mAdministratorLoginAuthority{nullptr};
    std::shared_ptr<UEventAnalysisToolBackend::Auth::AdministratorTokenVerifier>
        mAdministratorTokenVerifier{nullptr};
    std::shared_ptr<UEventAnalysisToolBackend::Auth::UserAdministration>
        mUserAdministration{nullptr};
    std::shared_ptr<UEventAnalysisToolBackend::Auth::UserLoginAuthority>
        mUserLoginAuthority{nullptr};
    std::shared_ptr<UEventAnalysisToolBackend::Auth::UserTokenVerifier>
        mUserTokenVerifier{nullptr};
    std::unique_ptr<UEventAnalysisToolBackend::GRPC::Server> mServer{nullptr};
    std::map<std::string, std::future<void>> mFuturesMap;
    mutable std::mutex mStopMutex;
    std::condition_variable mStopCondition;
    std::chrono::seconds mLastReport
    {
        std::chrono::duration_cast<std::chrono::seconds>
        ((std::chrono::high_resolution_clock::now()).time_since_epoch())
    };
    std::atomic<bool> mKeepRunning{true};
    bool mStopRequested{false};
    bool mIsRunning{false};
};

int main(int argc, char *argv[])
{
    namespace UEAT = UEventAnalysisToolBackend;

    //NOLINTNEXTLINE(misc-include-cleaner)
    auto consoleLogger = spdlog::stdout_color_st("console");
    SPDLOG_LOGGER_INFO(consoleLogger,
                       "Running version {} of uEventAnalysisToolBackend",
                       UEAT::Version::getVersionWithTag());
    // Ensure sodium is ready to go
    if (sodium_init() ==-1)
    {
        SPDLOG_LOGGER_CRITICAL(consoleLogger, "Failed to initialize sodium");
        return EXIT_FAILURE;
    } 
    // Initialize the metrics singleton once and for all

    // Parse the command line arguments
    std::filesystem::path iniFile;
    try
    {
        auto [iniFileName, isHelp] = ::parseCommandLineOptions(argc, argv);
        if (isHelp){return EXIT_SUCCESS;}
        if (iniFileName.empty())
        {
            throw std::runtime_error("No initialization file specified");
        }
        iniFile = iniFileName;
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_CRITICAL(consoleLogger,
                               "Failed to read command line options because {}",
                               std::string {e.what()});
        return EXIT_FAILURE;
    }

    // Get the program options
    ::ProgramOptions programOptions;
    try
    {
        programOptions.parseInitializationFile(iniFile);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_CRITICAL(consoleLogger,
                               "Failed to read program options because {}",
                               std::string {e.what()});
        return EXIT_FAILURE;
    }

    if ((programOptions.exportLogs || programOptions.exportMetrics) &&
        std::getenv("OTEL_SERVICE_NAME") == nullptr)
    {
        constexpr int overwrite{1};
        setenv("OTEL_SERVICE_NAME",
               programOptions.applicationName.c_str(),
               overwrite);
    }

    // Create the real logger
    std::shared_ptr<spdlog::logger> logger{nullptr};
    try
    {
        logger = UEventAnalysisToolBackend::Logger::initialize(programOptions);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_CRITICAL(consoleLogger,
                               "Failed to initialize logger because {}",
                               std::string {e.what()});
        return EXIT_FAILURE;
    }

/*
try
{
UEventAnalysisToolBackend::Database::AQMS::AQMS aqms{programOptions.aqmsCredentials, logger};
const std::chrono::seconds t0{1780323558};//t0{1784403392};
aqms.getEvents(t0);
}
catch (const std::exception &e)
{
  SPDLOG_LOGGER_ERROR(logger, "{}", e.what());
  UEventAnalysisToolBackend::Logger::cleanup();
  return EXIT_FAILURE;
}
*/

    std::unique_ptr<::Process> process{nullptr};
    try
    {
        process = std::make_unique<::Process> (programOptions, logger);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_CRITICAL(logger,
                               "Failed to initialize main process. Reason: {}",
                               std::string {e.what()});
        UEventAnalysisToolBackend::Logger::cleanup();
        return EXIT_FAILURE;
    }

    try
    {
         process->start();
         UEventAnalysisToolBackend::Logger::cleanup();
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_CRITICAL(logger,
                               "Application failed because {}",
                               std::string {e.what()});
        UEventAnalysisToolBackend::Logger::cleanup();
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS; 
}

