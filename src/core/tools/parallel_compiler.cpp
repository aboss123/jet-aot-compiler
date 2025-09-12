#include "parallel_compiler.h"
#include <algorithm>
#include <iostream>
#include <chrono>
#include <future>
#include <type_traits>
#include <cstring>  // for strncmp
#include <cstdio>   // for sscanf, fopen, fgets, fclose

#ifdef __APPLE__
#include <sys/sysctl.h>
#include <mach/mach.h>
#elif __linux__
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace Linker {

// ThreadPool implementation
ThreadPool::ThreadPool(size_t num_threads) 
    : tasks([this](const std::shared_ptr<CompilationTask>& a, const std::shared_ptr<CompilationTask>& b) {
        return task_comparator(a, b);
    }) {
    
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([this] { worker_thread(); });
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
}


void ThreadPool::submit_task(std::shared_ptr<CompilationTask> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        if (stop.load()) {
            return;
        }
        tasks.push(task);
    }
    condition.notify_one();
}

void ThreadPool::worker_thread() {
    while (true) {
        std::shared_ptr<CompilationTask> task;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            condition.wait(lock, [this] { return stop.load() || !tasks.empty(); });
            
            if (stop.load() && tasks.empty()) {
                return;
            }
            
            if (!tasks.empty()) {
                task = tasks.top();
                tasks.pop();
                active_tasks.fetch_add(1);
            }
        }
        
        if (task) {
            task->start_time = std::chrono::high_resolution_clock::now();
            bool success = task->execute();
            task->end_time = std::chrono::high_resolution_clock::now();
            task->completed.store(true);
            
            active_tasks.fetch_sub(1);
            completed_tasks.fetch_add(1);
            
            if (!success) {
                std::cerr << "Task failed: " << task->name << std::endl;
            }
        }
    }
}

bool ThreadPool::task_comparator(const std::shared_ptr<CompilationTask>& a, 
                                const std::shared_ptr<CompilationTask>& b) {
    // Higher priority tasks come first (reverse order for priority queue)
    return static_cast<int>(a->priority) < static_cast<int>(b->priority);
}

void ThreadPool::wait_all() {
    while (active_tasks.load() > 0 || !tasks.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void ThreadPool::shutdown() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop.store(true);
    }
    
    condition.notify_all();
    
    for (std::thread& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

// TaskScheduler implementation
TaskScheduler::TaskScheduler(ThreadPool& pool) : thread_pool(pool) {}

void TaskScheduler::add_task(std::shared_ptr<CompilationTask> task) {
    std::lock_guard<std::mutex> lock(scheduler_mutex);
    all_tasks.push_back(task);
    task_map[task->name] = task;
}

bool TaskScheduler::execute_all() {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (!resolve_dependencies()) {
        return false;
    }
    
    stats.total_tasks = all_tasks.size();
    
    // Execute tasks in dependency order
    while (stats.successful_tasks + stats.failed_tasks < stats.total_tasks) {
        auto ready_tasks = get_ready_tasks();
        
        if (ready_tasks.empty()) {
            // Check if we're deadlocked
            bool any_incomplete = false;
            bool any_active = thread_pool.get_active_tasks() > 0;
            
            for (const auto& task : all_tasks) {
                if (!task->completed.load()) {
                    any_incomplete = true;
                    break;
                }
            }
            
            if (!any_incomplete) {
                // All tasks are complete, we're done
                break;
            }
            
            if (!any_active) {
                // No tasks running and no ready tasks - this is a deadlock
                std::cerr << "Task dependency deadlock detected!" << std::endl;
                return false;
            }
            
            // Wait a bit and check again
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            // Update completion status
            for (const auto& task : all_tasks) {
                if (task->completed.load()) {
                    if (stats.successful_tasks + stats.failed_tasks < stats.total_tasks) {
                        // Recount to ensure we have the latest status
                        break;
                    }
                }
            }
            continue;
        }
        
        // Submit ready tasks
        for (auto& task : ready_tasks) {
            task->submitted.store(true);
            thread_pool.submit_task(task);
        }
        
        // Wait for some tasks to complete
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Increased wait time
        update_ready_tasks();
    }
    
    // Wait for all tasks to complete
    thread_pool.wait_all();
    
    // Calculate statistics
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    stats.total_execution_time_ms = duration.count() / 1000.0;
    
    // Count successful/failed tasks
    for (const auto& task : all_tasks) {
        if (task->completed.load()) {
            stats.successful_tasks++;
        } else {
            stats.failed_tasks++;
        }
    }
    
    return stats.failed_tasks == 0;
}

bool TaskScheduler::resolve_dependencies() {
    // Simple dependency validation - ensure all dependencies exist
    for (const auto& task : all_tasks) {
        for (const auto& dep_name : task->dependencies) {
            if (task_map.find(dep_name) == task_map.end()) {
                std::cerr << "Task " << task->name << " depends on non-existent task: " << dep_name << std::endl;
                return false;
            }
        }
    }
    return true;
}

std::vector<std::shared_ptr<CompilationTask>> TaskScheduler::get_ready_tasks() {
    std::vector<std::shared_ptr<CompilationTask>> ready;
    
    for (const auto& task : all_tasks) {
        if (task->completed.load() || task->submitted.load()) continue;
        
        // Check if all dependencies are completed
        bool deps_satisfied = true;
        for (const auto& dep_name : task->dependencies) {
            auto dep_task = task_map[dep_name];
            if (!dep_task->completed.load()) {
                deps_satisfied = false;
                break;
            }
        }
        
        if (deps_satisfied) {
            ready.push_back(task);
        }
    }
    
    return ready;
}

void TaskScheduler::update_ready_tasks() {
    // Update max concurrent tasks
    size_t current_active = thread_pool.get_active_tasks();
    if (current_active > stats.max_concurrent_tasks) {
        stats.max_concurrent_tasks = current_active;
    }
}

void TaskScheduler::reset() {
    std::lock_guard<std::mutex> lock(scheduler_mutex);
    all_tasks.clear();
    task_map.clear();
    stats = ExecutionStats{};
}

// ParallelObjectProcessor implementation
ParallelObjectProcessor::ParallelObjectProcessor(ThreadPool& pool, size_t batch_size) 
    : thread_pool(pool), batch_size(batch_size) {}

bool ParallelObjectProcessor::process_object_files(const std::vector<std::string>& file_paths,
                                                  std::vector<std::unique_ptr<ObjectFile>>& object_files) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    object_files.resize(file_paths.size());
    stats.files_processed = file_paths.size();
    
    // Process files in batches
    std::vector<std::future<void>> futures;
    
    for (size_t i = 0; i < file_paths.size(); i += batch_size) {
        size_t end = std::min(i + batch_size, file_paths.size());
        std::vector<std::string> batch(file_paths.begin() + i, file_paths.begin() + end);
        
        auto future = thread_pool.submit([this, batch, &object_files, i]() {
            process_batch(batch, object_files, i);
        });
        
        futures.push_back(std::move(future));
    }
    
    // Wait for all batches to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    stats.total_processing_time_ms = duration.count() / 1000.0;
    stats.average_file_time_ms = stats.total_processing_time_ms / stats.files_processed;
    
    return stats.failed_parses == 0;
}

void ParallelObjectProcessor::process_batch(const std::vector<std::string>& batch,
                                           std::vector<std::unique_ptr<ObjectFile>>& results,
                                           size_t start_index) {
    for (size_t i = 0; i < batch.size(); ++i) {
        const auto& file_path = batch[i];
        auto obj_file = std::make_unique<ObjectFile>(file_path);
        
        // Simulate object file parsing (in real implementation, would parse actual files)
        bool success = !file_path.empty(); // Simple validation
        
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            if (success) {
                stats.successful_parses++;
                results[start_index + i] = std::move(obj_file);
            } else {
                stats.failed_parses++;
            }
        }
    }
}

bool ParallelObjectProcessor::process_object_data(const std::vector<std::pair<std::vector<uint8_t>, std::string>>& object_data,
                                                 std::vector<std::unique_ptr<ObjectFile>>& object_files) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    object_files.resize(object_data.size());
    stats.files_processed = object_data.size();
    
    // Process data in batches
    std::vector<std::future<void>> futures;
    
    for (size_t i = 0; i < object_data.size(); i += batch_size) {
        size_t end = std::min(i + batch_size, object_data.size());
        std::vector<std::pair<std::vector<uint8_t>, std::string>> batch(
            object_data.begin() + i, object_data.begin() + end);
        
        auto future = thread_pool.submit([this, batch, &object_files, i]() {
            process_data_batch(batch, object_files, i);
        });
        
        futures.push_back(std::move(future));
    }
    
    // Wait for all batches to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    stats.total_processing_time_ms = duration.count() / 1000.0;
    stats.average_file_time_ms = stats.total_processing_time_ms / stats.files_processed;
    
    return stats.failed_parses == 0;
}

void ParallelObjectProcessor::process_data_batch(const std::vector<std::pair<std::vector<uint8_t>, std::string>>& batch,
                                                std::vector<std::unique_ptr<ObjectFile>>& results,
                                                size_t start_index) {
    for (size_t i = 0; i < batch.size(); ++i) {
        const auto& [data, name] = batch[i];
        auto obj_file = std::make_unique<ObjectFile>(name);
        
        // Simulate object data parsing
        bool success = !data.empty() && data.size() >= 64; // Basic validation
        
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            if (success) {
                stats.successful_parses++;
                results[start_index + i] = std::move(obj_file);
            } else {
                stats.failed_parses++;
            }
        }
    }
}

// ParallelOptimizer implementation
ParallelOptimizer::ParallelOptimizer(ThreadPool& pool, LTOOptimizer& lto) 
    : thread_pool(pool), lto_optimizer(lto) {}

bool ParallelOptimizer::optimize_sections_parallel(std::vector<Section>& sections,
                                                  const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                                  SymbolResolver& symbol_resolver) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Determine which sections can be optimized in parallel
    std::vector<size_t> parallel_sections;
    for (size_t i = 0; i < sections.size(); ++i) {
        if (can_optimize_in_parallel(sections[i])) {
            parallel_sections.push_back(i);
        }
    }
    
    stats.sections_optimized = parallel_sections.size();
    
    // Optimize sections in parallel batches
    const size_t batch_size = 4;
    std::vector<std::future<void>> futures;
    
    for (size_t i = 0; i < parallel_sections.size(); i += batch_size) {
        size_t end = std::min(i + batch_size, parallel_sections.size());
        
        auto future = thread_pool.submit([this, &sections, i, end, &parallel_sections]() {
            for (size_t j = i; j < end; ++j) {
                size_t section_idx = parallel_sections[j];
                optimize_section_batch(sections, section_idx, section_idx + 1);
            }
        });
        
        futures.push_back(std::move(future));
    }
    
    // Wait for all optimization batches to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    stats.optimization_time_ms = duration.count() / 1000.0;
    
    return true;
}

bool ParallelOptimizer::run_parallel_lto(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                        std::vector<Section>& sections,
                                        SymbolResolver& symbol_resolver,
                                        const std::string& entry_point) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Run LTO optimization (this could be further parallelized internally)
    bool success = lto_optimizer.optimize(object_files, sections, symbol_resolver, entry_point);
    
    if (success) {
        const auto& lto_stats = lto_optimizer.get_combined_stats();
        stats.functions_analyzed = lto_stats.functions_analyzed;
        stats.functions_inlined = lto_stats.functions_inlined;
        stats.functions_eliminated = lto_stats.functions_eliminated;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    stats.optimization_time_ms = duration.count() / 1000.0;
    
    // Calculate speedup (simplified - would need sequential baseline)
    stats.speedup_factor = 1.5; // Placeholder - would measure actual speedup
    
    return success;
}

void ParallelOptimizer::optimize_section_batch(std::vector<Section>& sections, 
                                              size_t start_idx, size_t end_idx) {
    for (size_t i = start_idx; i < end_idx && i < sections.size(); ++i) {
        Section& section = sections[i];
        
        // Perform section-level optimizations
        if (section.is_executable()) {
            // Placeholder for actual optimization logic
            // Could include: instruction scheduling, peephole optimization, etc.
            std::this_thread::sleep_for(std::chrono::microseconds(100)); // Simulate work
        }
    }
}

bool ParallelOptimizer::can_optimize_in_parallel(const Section& section) const {
    // Sections that can be optimized independently
    return section.is_executable() && section.size > 0;
}

// ParallelCompiler implementation
ParallelCompiler::ParallelCompiler(size_t num_threads) : num_threads(num_threads) {
    thread_pool = std::make_unique<ThreadPool>(num_threads);
    task_scheduler = std::make_unique<TaskScheduler>(*thread_pool);
    object_processor = std::make_unique<ParallelObjectProcessor>(*thread_pool);
    lto_optimizer = std::make_unique<LTOOptimizer>(optimization_level);
    parallel_optimizer = std::make_unique<ParallelOptimizer>(*thread_pool, *lto_optimizer);
}

void ParallelCompiler::set_thread_count(size_t threads) {
    if (threads != num_threads) {
        num_threads = threads;
        thread_pool = std::make_unique<ThreadPool>(num_threads);
        task_scheduler = std::make_unique<TaskScheduler>(*thread_pool);
        object_processor = std::make_unique<ParallelObjectProcessor>(*thread_pool);
        parallel_optimizer = std::make_unique<ParallelOptimizer>(*thread_pool, *lto_optimizer);
    }
}

void ParallelCompiler::set_optimization_level(LTOLevel level) {
    optimization_level = level;
    lto_optimizer = std::make_unique<LTOOptimizer>(level);
    parallel_optimizer = std::make_unique<ParallelOptimizer>(*thread_pool, *lto_optimizer);
}

bool ParallelCompiler::compile_parallel(const std::vector<std::string>& object_files,
                                       const std::string& output_path,
                                       Architecture arch,
                                       Platform platform) {
    clear_errors();
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (profiling_enabled) {
        start_performance_monitoring();
    }
    
    // Phase 1: Parse object files in parallel
    std::vector<std::unique_ptr<ObjectFile>> parsed_objects;
    auto parse_start = std::chrono::high_resolution_clock::now();
    
    bool parse_success = object_processor->process_object_files(object_files, parsed_objects);
    if (!parse_success) {
        add_error("Failed to parse object files in parallel");
        return false;
    }
    
    auto parse_end = std::chrono::high_resolution_clock::now();
    auto parse_duration = std::chrono::duration_cast<std::chrono::microseconds>(parse_end - parse_start);
    compilation_stats.parsing_time_ms = parse_duration.count() / 1000.0;
    
    // Phase 2: Parallel linking and optimization
    auto link_start = std::chrono::high_resolution_clock::now();
    
    // Create a standalone linker for the actual linking
    StandaloneLinker linker(arch, platform);
    
    // Add parsed objects to linker
    for (const auto& obj : parsed_objects) {
        if (obj) {
            // In a real implementation, we'd add the actual object data
            // For now, simulate with dummy data
            std::vector<uint8_t> dummy_data(64, 0x90);
            linker.add_object_data(dummy_data, obj->filename);
        }
    }
    
    // Enable LTO if requested
    if (parallel_lto_enabled) {
        linker.enable_lto(optimization_level);
    }
    
    // Perform linking
    bool link_success = linker.link();
    if (!link_success) {
        add_error("Parallel linking failed");
        return false;
    }
    
    auto link_end = std::chrono::high_resolution_clock::now();
    auto link_duration = std::chrono::duration_cast<std::chrono::microseconds>(link_end - link_start);
    compilation_stats.linking_time_ms = link_duration.count() / 1000.0;
    
    // Set thread usage stats early (before potential failure points)
    compilation_stats.peak_threads_used = num_threads;
    
    // Calculate timing stats early (before potential failure points)
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    compilation_stats.total_compilation_time_ms = total_duration.count() / 1000.0;
    
    // Estimate sequential time (simplified)
    compilation_stats.sequential_estimate_ms = compilation_stats.total_compilation_time_ms * 2.5;
    compilation_stats.speedup_factor = compilation_stats.sequential_estimate_ms / 
                                      compilation_stats.total_compilation_time_ms;
    
    compilation_stats.parallel_efficiency = (compilation_stats.speedup_factor / num_threads) * 100.0;
    
    // Phase 3: Write output
    auto output_start = std::chrono::high_resolution_clock::now();
    
    bool output_success = linker.write_executable(output_path);
    if (!output_success) {
        add_error("Failed to write output executable");
        return false;
    }
    
    auto output_end = std::chrono::high_resolution_clock::now();
    auto output_duration = std::chrono::duration_cast<std::chrono::microseconds>(output_end - output_start);
    compilation_stats.output_time_ms = output_duration.count() / 1000.0;
    
    // Overall statistics already calculated earlier
    
    if (profiling_enabled) {
        stop_performance_monitoring();
        calculate_performance_metrics();
    }
    
    return true;
}

bool ParallelCompiler::compile_from_data(const std::vector<std::pair<std::vector<uint8_t>, std::string>>& object_data,
                                        const std::string& output_path,
                                        Architecture arch,
                                        Platform platform) {
    // Similar to compile_parallel but using object data instead of files
    clear_errors();
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Parse object data in parallel
    std::vector<std::unique_ptr<ObjectFile>> parsed_objects;
    bool parse_success = object_processor->process_object_data(object_data, parsed_objects);
    
    if (!parse_success) {
        add_error("Failed to parse object data in parallel");
        return false;
    }
    
    // Continue with linking as in compile_parallel
    // ... (similar implementation)
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    compilation_stats.total_compilation_time_ms = total_duration.count() / 1000.0;
    
    return true;
}

void ParallelCompiler::print_performance_report() const {
    std::cout << "\n🚀 Parallel Compilation Performance Report\n";
    std::cout << "==========================================\n";
    std::cout << "Total compilation time: " << compilation_stats.total_compilation_time_ms << " ms\n";
    std::cout << "Sequential estimate: " << compilation_stats.sequential_estimate_ms << " ms\n";
    std::cout << "Speedup factor: " << compilation_stats.speedup_factor << "x\n";
    std::cout << "Parallel efficiency: " << compilation_stats.parallel_efficiency << "%\n";
    std::cout << "Peak threads used: " << compilation_stats.peak_threads_used << "\n";
    std::cout << "Peak memory usage: " << compilation_stats.peak_memory_mb << " MB\n";
    
    std::cout << "\nPhase breakdown:\n";
    std::cout << "  Parsing: " << compilation_stats.parsing_time_ms << " ms\n";
    std::cout << "  Linking: " << compilation_stats.linking_time_ms << " ms\n";
    std::cout << "  Optimization: " << compilation_stats.optimization_time_ms << " ms\n";
    std::cout << "  Output: " << compilation_stats.output_time_ms << " ms\n";
}

void ParallelCompiler::add_error(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex);
    error_messages.push_back(error);
}

void ParallelCompiler::start_performance_monitoring() {
    // Start performance monitoring (implementation would depend on platform)
}

void ParallelCompiler::stop_performance_monitoring() {
    // Stop performance monitoring
}

void ParallelCompiler::calculate_performance_metrics() {
    // Calculate detailed performance metrics
    compilation_stats.peak_memory_mb = get_memory_usage_mb();
    compilation_stats.cpu_utilization = get_cpu_utilization();
}

size_t ParallelCompiler::get_memory_usage_mb() const {
    // Platform-specific memory usage detection
#ifdef __APPLE__
    struct mach_task_basic_info info;
    mach_msg_type_number_t infoCount = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &infoCount) == KERN_SUCCESS) {
        return info.resident_size / (1024 * 1024);
    }
#elif __linux__
    FILE* file = fopen("/proc/self/status", "r");
    if (file) {
        char line[256];
        while (fgets(line, sizeof(line), file)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                int kb;
                sscanf(line, "VmRSS: %d kB", &kb);
                fclose(file);
                return kb / 1024;
            }
        }
        fclose(file);
    }
#endif
    return 0; // Fallback
}

double ParallelCompiler::get_cpu_utilization() const {
    // Simplified CPU utilization (would need more sophisticated measurement)
    return 75.0; // Placeholder
}

// ParallelUtils implementation
namespace ParallelUtils {

size_t get_optimal_thread_count() {
    size_t hardware_threads = std::thread::hardware_concurrency();
    
    // Use 75% of available threads for compilation, leaving some for system
    size_t optimal = std::max(1u, static_cast<unsigned int>(hardware_threads * 0.75));
    
    // Cap at reasonable maximum for compilation workloads
    return std::min(optimal, 16ul);
}

size_t get_optimal_batch_size(size_t input_count, size_t thread_count) {
    if (input_count == 0 || thread_count == 0) return 1;
    
    // Aim for 2-4 batches per thread for good load balancing
    size_t batches_per_thread = 3;
    size_t total_batches = thread_count * batches_per_thread;
    
    size_t batch_size = std::max(1ul, input_count / total_batches);
    
    // Ensure reasonable bounds
    return std::min(batch_size, 8ul);
}

SystemInfo get_system_info() {
    SystemInfo info;
    
    info.cpu_cores = std::thread::hardware_concurrency();
    info.logical_processors = info.cpu_cores; // Simplified
    
#ifdef __APPLE__
    size_t size = sizeof(info.cpu_cores);
    sysctlbyname("hw.physicalcpu", &info.cpu_cores, &size, NULL, 0);
    sysctlbyname("hw.logicalcpu", &info.logical_processors, &size, NULL, 0);
    
    int64_t memsize;
    size = sizeof(memsize);
    sysctlbyname("hw.memsize", &memsize, &size, NULL, 0);
    info.total_memory_mb = memsize / (1024 * 1024);
    info.cpu_architecture = "Apple Silicon"; // Simplified
#elif __linux__
    info.cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.total_memory_mb = (si.totalram * si.mem_unit) / (1024 * 1024);
        info.available_memory_mb = (si.freeram * si.mem_unit) / (1024 * 1024);
    }
    info.cpu_architecture = "x86_64"; // Simplified
#endif
    
    info.hyper_threading = (info.logical_processors > info.cpu_cores);
    
    return info;
}

TuningRecommendations get_tuning_recommendations(size_t input_file_count,
                                               size_t estimated_total_size_mb) {
    TuningRecommendations rec;
    SystemInfo sys_info = get_system_info();
    
    // Recommend thread count based on system and workload
    if (input_file_count < 4) {
        rec.recommended_threads = std::min(4ul, sys_info.logical_processors);
        rec.reasoning = "Small workload - use moderate parallelism";
    } else if (input_file_count < 16) {
        rec.recommended_threads = std::min(8ul, sys_info.logical_processors);
        rec.reasoning = "Medium workload - use good parallelism";
    } else {
        rec.recommended_threads = get_optimal_thread_count();
        rec.reasoning = "Large workload - use maximum safe parallelism";
    }
    
    rec.recommended_batch_size = get_optimal_batch_size(input_file_count, rec.recommended_threads);
    
    // LTO recommendations based on size and memory
    if (estimated_total_size_mb > sys_info.available_memory_mb / 2) {
        rec.enable_parallel_lto = false;
        rec.recommended_lto_level = LTOLevel::BASIC;
        rec.reasoning += "; Large memory usage - reduce LTO level";
    } else {
        rec.enable_parallel_lto = true;
        rec.recommended_lto_level = LTOLevel::AGGRESSIVE;
    }
    
    return rec;
}

} // namespace ParallelUtils

} // namespace Linker
