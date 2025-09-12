#pragma once
#include "standalone_linker.h"
#include "lto_optimizer.h"
#include <thread>
#include <future>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <type_traits>

namespace Linker {

// Forward declarations
class ParallelCompiler;
class ThreadPool;
class TaskScheduler;
class ParallelLinker;

// Compilation task types
enum class TaskType {
    PARSE_OBJECT,
    MERGE_SECTIONS,
    RESOLVE_SYMBOLS,
    APPLY_RELOCATIONS,
    OPTIMIZE_CODE,
    GENERATE_OUTPUT
};

// Task priority levels
enum class TaskPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

// Compilation task representation
struct CompilationTask {
    TaskType type;
    TaskPriority priority;
    std::string name;
    std::function<bool()> execute;
    std::vector<std::string> dependencies;
    std::atomic<bool> completed{false};
    std::atomic<bool> submitted{false};
    std::chrono::high_resolution_clock::time_point start_time;
    std::chrono::high_resolution_clock::time_point end_time;
    
    CompilationTask() = default;
    CompilationTask(TaskType t, TaskPriority p, const std::string& n, std::function<bool()> exec)
        : type(t), priority(p), name(n), execute(std::move(exec)) {}
    
    double get_execution_time_ms() const {
        if (completed.load()) {
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            return duration.count() / 1000.0;
        }
        return 0.0;
    }
};

// Thread pool for parallel execution
class ThreadPool {
public:
    ThreadPool(size_t num_threads = std::thread::hardware_concurrency());
    ~ThreadPool();
    
    // Submit a task for execution
    template<class F, class... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::invoke_result<F, Args...>::type> {
        using return_type = typename std::invoke_result<F, Args...>::type;
        
        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        
        std::future<return_type> result = task->get_future();
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop.load()) {
                throw std::runtime_error("ThreadPool is stopped");
            }
            
            auto compilation_task = std::make_shared<CompilationTask>(
                TaskType::OPTIMIZE_CODE,
                TaskPriority::NORMAL,
                "generic_task",
                [task]() -> bool {
                    (*task)();
                    return true;
                }
            );
            
            tasks.push(compilation_task);
        }
        
        condition.notify_one();
        return result;
    }
    
    // Submit a task with priority
    void submit_task(std::shared_ptr<CompilationTask> task);
    
    // Wait for all tasks to complete
    void wait_all();
    
    // Get thread pool statistics
    size_t get_thread_count() const { return workers.size(); }
    size_t get_active_tasks() const { return active_tasks.load(); }
    size_t get_completed_tasks() const { return completed_tasks.load(); }
    
    // Shutdown the thread pool
    void shutdown();
    
private:
    std::vector<std::thread> workers;
    std::priority_queue<std::shared_ptr<CompilationTask>, 
                       std::vector<std::shared_ptr<CompilationTask>>, 
                       std::function<bool(const std::shared_ptr<CompilationTask>&, 
                                        const std::shared_ptr<CompilationTask>&)>> tasks;
    
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop{false};
    std::atomic<size_t> active_tasks{0};
    std::atomic<size_t> completed_tasks{0};
    
    void worker_thread();
    bool task_comparator(const std::shared_ptr<CompilationTask>& a, 
                        const std::shared_ptr<CompilationTask>& b);
};

// Task dependency manager and scheduler
class TaskScheduler {
public:
    TaskScheduler(ThreadPool& pool);
    ~TaskScheduler() = default;
    
    // Add a task with dependencies
    void add_task(std::shared_ptr<CompilationTask> task);
    
    // Execute all tasks respecting dependencies
    bool execute_all();
    
    // Get execution statistics
    struct ExecutionStats {
        size_t total_tasks = 0;
        size_t successful_tasks = 0;
        size_t failed_tasks = 0;
        double total_execution_time_ms = 0.0;
        double parallel_efficiency = 0.0; // vs sequential execution
        size_t max_concurrent_tasks = 0;
        
        double get_success_rate() const {
            return total_tasks > 0 ? (double)successful_tasks / total_tasks * 100.0 : 0.0;
        }
    };
    
    const ExecutionStats& get_stats() const { return stats; }
    
    // Clear all tasks and reset
    void reset();
    
private:
    ThreadPool& thread_pool;
    std::vector<std::shared_ptr<CompilationTask>> all_tasks;
    std::unordered_map<std::string, std::shared_ptr<CompilationTask>> task_map;
    std::mutex scheduler_mutex;
    ExecutionStats stats;
    
    // Dependency resolution
    bool resolve_dependencies();
    std::vector<std::shared_ptr<CompilationTask>> get_ready_tasks();
    void update_ready_tasks();
};

// Parallel object file processor
class ParallelObjectProcessor {
public:
    ParallelObjectProcessor(ThreadPool& pool, size_t batch_size = 4);
    ~ParallelObjectProcessor() = default;
    
    // Process multiple object files in parallel
    bool process_object_files(const std::vector<std::string>& file_paths,
                             std::vector<std::unique_ptr<ObjectFile>>& object_files);
    
    // Process object data in parallel
    bool process_object_data(const std::vector<std::pair<std::vector<uint8_t>, std::string>>& object_data,
                            std::vector<std::unique_ptr<ObjectFile>>& object_files);
    
    // Get processing statistics
    struct ProcessingStats {
        size_t files_processed = 0;
        size_t successful_parses = 0;
        size_t failed_parses = 0;
        double total_processing_time_ms = 0.0;
        double average_file_time_ms = 0.0;
        size_t peak_memory_usage_mb = 0;
        
        double get_success_rate() const {
            return files_processed > 0 ? (double)successful_parses / files_processed * 100.0 : 0.0;
        }
    };
    
    const ProcessingStats& get_stats() const { return stats; }
    
private:
    ThreadPool& thread_pool;
    size_t batch_size;
    ProcessingStats stats;
    std::mutex stats_mutex;
    
    // Batch processing helpers
    void process_batch(const std::vector<std::string>& batch,
                      std::vector<std::unique_ptr<ObjectFile>>& results,
                      size_t start_index);
    
    void process_data_batch(const std::vector<std::pair<std::vector<uint8_t>, std::string>>& batch,
                           std::vector<std::unique_ptr<ObjectFile>>& results,
                           size_t start_index);
};

// Parallel optimization engine
class ParallelOptimizer {
public:
    ParallelOptimizer(ThreadPool& pool, LTOOptimizer& lto);
    ~ParallelOptimizer() = default;
    
    // Run optimization passes in parallel
    bool optimize_sections_parallel(std::vector<Section>& sections,
                                   const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                   SymbolResolver& symbol_resolver);
    
    // Parallel LTO optimization
    bool run_parallel_lto(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                         std::vector<Section>& sections,
                         SymbolResolver& symbol_resolver,
                         const std::string& entry_point);
    
    // Get optimization statistics
    struct OptimizationStats {
        size_t sections_optimized = 0;
        size_t functions_analyzed = 0;
        size_t functions_inlined = 0;
        size_t functions_eliminated = 0;
        double optimization_time_ms = 0.0;
        double speedup_factor = 1.0; // vs sequential
        size_t memory_peak_mb = 0;
        
        double get_optimization_rate() const {
            return optimization_time_ms > 0 ? functions_analyzed / optimization_time_ms * 1000.0 : 0.0;
        }
    };
    
    const OptimizationStats& get_stats() const { return stats; }
    
private:
    ThreadPool& thread_pool;
    LTOOptimizer& lto_optimizer;
    OptimizationStats stats;
    std::mutex stats_mutex;
    
    // Parallel optimization helpers
    void optimize_section_batch(std::vector<Section>& sections, 
                               size_t start_idx, size_t end_idx);
    
    bool can_optimize_in_parallel(const Section& section) const;
};

// Main parallel compiler coordinator
class ParallelCompiler {
public:
    ParallelCompiler(size_t num_threads = std::thread::hardware_concurrency());
    ~ParallelCompiler() = default;
    
    // Configuration
    void set_thread_count(size_t threads);
    void set_batch_size(size_t batch_size) { object_processor.reset(); } // Recreate with new batch size
    void enable_parallel_lto(bool enabled) { parallel_lto_enabled = enabled; }
    void set_optimization_level(LTOLevel level);
    
    // Parallel compilation pipeline
    bool compile_parallel(const std::vector<std::string>& object_files,
                         const std::string& output_path,
                         Architecture arch = Architecture::X86_64,
                         Platform platform = Platform::LINUX);
    
    // Compile from object data
    bool compile_from_data(const std::vector<std::pair<std::vector<uint8_t>, std::string>>& object_data,
                          const std::string& output_path,
                          Architecture arch = Architecture::X86_64,
                          Platform platform = Platform::LINUX);
    
    // Get comprehensive compilation statistics
    struct CompilationStats {
        // Overall timing
        double total_compilation_time_ms = 0.0;
        double sequential_estimate_ms = 0.0;
        double speedup_factor = 1.0;
        double parallel_efficiency = 0.0; // 0-100%
        
        // Task breakdown
        size_t total_tasks = 0;
        size_t successful_tasks = 0;
        double task_success_rate = 0.0;
        
        // Resource usage
        size_t peak_threads_used = 0;
        size_t peak_memory_mb = 0;
        double cpu_utilization = 0.0; // 0-100%
        
        // Phase timings
        double parsing_time_ms = 0.0;
        double linking_time_ms = 0.0;
        double optimization_time_ms = 0.0;
        double output_time_ms = 0.0;
        
        // Quality metrics
        size_t functions_optimized = 0;
        size_t code_size_reduction_bytes = 0;
        double optimization_effectiveness = 0.0;
    };
    
    const CompilationStats& get_stats() const { return compilation_stats; }
    
    // Performance profiling
    void enable_profiling(bool enabled) { profiling_enabled = enabled; }
    void print_performance_report() const;
    
    // Error handling
    const std::vector<std::string>& get_errors() const { return error_messages; }
    bool has_errors() const { return !error_messages.empty(); }
    void clear_errors() { error_messages.clear(); }
    
private:
    std::unique_ptr<ThreadPool> thread_pool;
    std::unique_ptr<TaskScheduler> task_scheduler;
    std::unique_ptr<ParallelObjectProcessor> object_processor;
    std::unique_ptr<ParallelOptimizer> parallel_optimizer;
    std::unique_ptr<LTOOptimizer> lto_optimizer;
    
    size_t num_threads;
    bool parallel_lto_enabled = true;
    bool profiling_enabled = false;
    LTOLevel optimization_level = LTOLevel::AGGRESSIVE;
    
    CompilationStats compilation_stats;
    std::vector<std::string> error_messages;
    std::mutex error_mutex;
    
    // Internal compilation pipeline
    bool setup_compilation_pipeline(Architecture arch, Platform platform);
    bool create_compilation_tasks(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                 const std::string& output_path);
    
    // Performance monitoring
    void start_performance_monitoring();
    void stop_performance_monitoring();
    void calculate_performance_metrics();
    
    // Error handling
    void add_error(const std::string& error);
    
    // Resource monitoring
    size_t get_memory_usage_mb() const;
    double get_cpu_utilization() const;
};

// Utility functions for parallel compilation
namespace ParallelUtils {
    // Determine optimal thread count for current system
    size_t get_optimal_thread_count();
    
    // Determine optimal batch size based on input size
    size_t get_optimal_batch_size(size_t input_count, size_t thread_count);
    
    // System resource detection
    struct SystemInfo {
        size_t cpu_cores = 0;
        size_t logical_processors = 0;
        size_t total_memory_mb = 0;
        size_t available_memory_mb = 0;
        bool hyper_threading = false;
        std::string cpu_architecture;
    };
    
    SystemInfo get_system_info();
    
    // Performance tuning recommendations
    struct TuningRecommendations {
        size_t recommended_threads = 0;
        size_t recommended_batch_size = 0;
        bool enable_parallel_lto = true;
        LTOLevel recommended_lto_level = LTOLevel::AGGRESSIVE;
        std::string reasoning;
    };
    
    TuningRecommendations get_tuning_recommendations(size_t input_file_count,
                                                   size_t estimated_total_size_mb);
}

} // namespace Linker
