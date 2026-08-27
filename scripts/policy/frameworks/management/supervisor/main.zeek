


@load base/utils/paths
@load base/utils/queue

@load policy/frameworks/management/types
@load policy/frameworks/management/node/config

@load ./api
@load ./config

module Management::Supervisor;


type NodeOutputStreams: record {


	stdout: Queue::Queue;
	stderr: Queue::Queue;


	stdout_file: file &optional;
	stderr_file: file &optional;
};


global g_outputs: table[string] of NodeOutputStreams;

function make_node_output_streams(node: string): NodeOutputStreams
	{
	local stdout = Queue::init(Queue::Settings($max_len = Management::Supervisor::output_max_lines));
	local stderr = Queue::init(Queue::Settings($max_len = Management::Supervisor::output_max_lines));

	local res = NodeOutputStreams($stdout=stdout, $stderr=stderr);
	local status = Supervisor::status(node);

	if ( node !in status$nodes )
		return res;

	local ns = status$nodes[node];
	local directory = ".";

	if ( ns$node?$directory )
		directory = ns$node$directory;

	if ( Management::Node::stdout_file != "" )
		res$stdout_file = open(build_path(directory, Management::Node::stdout_file));
	if ( Management::Node::stderr_file != "" )
		res$stderr_file = open(build_path(directory, Management::Node::stderr_file));

	return res;
	}

hook Supervisor::stdout_hook(node: string, msg: string)
	{
	if ( node !in g_outputs )
		g_outputs[node] = make_node_output_streams(node);





	if ( g_outputs[node]?$stdout_file )
		{
		print g_outputs[node]$stdout_file, msg;
		flush_all();
		}


	Queue::put(g_outputs[node]$stdout, msg);

	if ( ! print_stdout )
		break;
	}

hook Supervisor::stderr_hook(node: string, msg: string)
	{
	if ( node !in g_outputs )
		g_outputs[node] = make_node_output_streams(node);

	if ( g_outputs[node]?$stderr_file )
		{
		print g_outputs[node]$stderr_file, msg;
		flush_all();
		}

	Queue::put(g_outputs[node]$stderr, msg);

	if ( ! print_stderr )
		break;
	}

event Supervisor::node_status(node: string, pid: count)
	{


	if ( node in g_outputs )
		{
		local stdout_lines: vector of string;
		local stderr_lines: vector of string;

		Queue::get_vector(g_outputs[node]$stdout, stdout_lines);
		Queue::get_vector(g_outputs[node]$stderr, stderr_lines);

		if ( |stdout_lines| > 0 || |stderr_lines| > 0 )
			{
			local outputs = Management::NodeOutputs(
			    $stdout = join_string_vec(stdout_lines, "\n"),
			    $stderr = join_string_vec(stderr_lines, "\n"));

			Broker::publish(topic_prefix, Management::Supervisor::API::notify_node_exit, node, outputs);
			}

		if ( g_outputs[node]?$stdout_file )
			close(g_outputs[node]$stdout_file);
		if ( g_outputs[node]?$stderr_file )
			close(g_outputs[node]$stderr_file);
		}

	g_outputs[node] = make_node_output_streams(node);
	}
