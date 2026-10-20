#ifndef COMMAND_LINE_OPTIONS_HPP
#define COMMAND_LINE_OPTIONS_HPP
#include <iostream>
#include <filesystem>
#include <string>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

namespace
{

std::pair<std::filesystem::path, bool>
    parseCommandLineOptions(int argc, char *argv[])
{
    std::filesystem::path iniFile;
    boost::program_options::options_description desc(R"""(
The uEventAnalysisToolBackend is the backend for the uEAT frontend.  
It sits between disparate microservices in the UUSS Kubernetes systems and
consolidates their functionality into an opinionated one-stop-shop for 
the frontend.  It can be run as follows:

    uEventAnalysisToolBackend --ini=bff.ini

Allowed options)""");
    desc.add_options()
        ("help", "Produces this help message")
        ("ini",  boost::program_options::value<std::string> (), 
                 "The initialization file for this executable");
    boost::program_options::variables_map vm; 
    //NOLINTBEGIN(misc-include-cleaner)
    auto parsedMap
        = boost::program_options::parse_command_line(argc, argv, desc);
    //NOLINTEND(misc-include-cleaner)
    boost::program_options::store(parsedMap, vm);
    boost::program_options::notify(vm);
    if (vm.count("help"))
    {   
        std::cout << desc << "\n";
        return {iniFile, true};
    }   
    if (vm.count("ini"))
    {   
        iniFile = vm["ini"].as<std::string> (); 
        if (!std::filesystem::exists(iniFile))
        {
            throw std::runtime_error("Initialization file: "
                                   + std::string {iniFile}
                                   + " does not exist");
        }
    }   
    return {iniFile, false};
}

}
#endif
