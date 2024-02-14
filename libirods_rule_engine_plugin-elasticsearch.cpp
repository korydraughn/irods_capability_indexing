#include "configuration.hpp"
#include "plugin_specific_configuration.hpp"
#include "utilities.hpp"

#include <irods/MD5Strategy.hpp>
#include <irods/irods_hasher_factory.hpp>
#include <irods/irods_log.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/rsModAVUMetadata.hpp>

#define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include <irods/irods_query.hpp>

#define IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
#include <irods/dstream.hpp>
#include <irods/transport/default_transport.hpp>

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include <irods/filesystem.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/any.hpp>
#include <boost/format.hpp>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/url.hpp>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{
	namespace beast = boost::beast;
	namespace http = beast::http;

	using json = nlohmann::json;

	auto send_http_request(const std::string_view _service_url,
						   http::verb _verb,
						   const std::string_view _target,
						   const std::string_view _body = "") -> std::optional<http::response<http::string_body>>
	{
		// TODO These host/port checks should happen at plugin startup.
		// There's no point paying for these on every http request.

		if (_service_url.empty()) {
			rodsLog(LOG_ERROR, "%s: Empty service URL.", __func__);
			return std::nullopt;
		}

		namespace urls = boost::urls;

		urls::result<urls::url_view> result = urls::parse_uri(_service_url);
		if (!result) {
			rodsLog(LOG_ERROR, fmt::format("{}: Could not parse service URL [{}].", __func__, _service_url).c_str());
			return std::nullopt;
		}

		namespace net = boost::asio;
		using tcp = net::ip::tcp;

		try {
			net::io_context ioc;

			tcp::resolver resolver{ioc};
			beast::tcp_stream stream{ioc};

			const auto results = resolver.resolve(result->host(), result->port());
			stream.connect(results);

			http::request<http::string_body> req{_verb, _target, 11};
			req.set(http::field::host, "localhost");
			req.set(http::field::user_agent, "iRODS Indexing Plugin/4.3.1");
			req.set(http::field::content_type, "application/json");

			if (!_body.empty()) {
				req.body() = _body;
				{
					std::stringstream ss;
					ss << req;
					const auto s = ss.str();
					if (s.size() > 256) {
						rodsLog(LOG_NOTICE, fmt::format("{}: sending request = (truncated) [{} ...]", __func__, s.substr(0, 256)).c_str());
					}
					else {
						rodsLog(LOG_NOTICE, fmt::format("{}: sending request = [{}]", __func__, s).c_str());
					}
				}
				req.prepare_payload();
			}

			http::write(stream, req);

			beast::flat_buffer buffer;
			http::response<http::string_body> res;
			http::read(stream, buffer, res);

			{
				std::stringstream ss;
				ss << res;
				rodsLog(LOG_NOTICE, fmt::format("{}: elasticsearch response = [{}]", __func__, ss.str()).c_str());
			}

			beast::error_code ec;
			stream.socket().shutdown(tcp::socket::shutdown_both, ec);

			// not_connected happens sometimes, so don't bother reporting it.
			if (ec && ec != beast::errc::not_connected) {
				throw beast::system_error{ec};
			}

			return res;
		}
		catch (const std::exception& e) {
			rodsLog(LOG_ERROR, fmt::format("{}: {}", __func__, e.what()).c_str());
		}

		return std::nullopt;
	}

	using string_t = std::string;

	struct configuration : irods::indexing::configuration
	{
		std::vector<std::string> hosts_;
		int bulk_count_{10};
		int read_size_{4194304};
		std::string es_version_{"7."};

		configuration(const std::string& _instance_name)
			: irods::indexing::configuration(_instance_name)
		{
			try {
				auto cfg = irods::indexing::get_plugin_specific_configuration(_instance_name);
				if (cfg.find("hosts") != cfg.end()) {
					nlohmann::json host_list = cfg.at("hosts");
					for (auto& i : host_list) {
						hosts_.push_back(i.get<std::string>());
					}
				}

				if (cfg.find("es_version") != cfg.end()) {
					es_version_ = cfg.at("es_version").get<std::string>();
				}

				if (cfg.find("bulk_count") != cfg.end()) {
					bulk_count_ = cfg.at("bulk_count").get<int>();
				}

				if (cfg.find("read_size") != cfg.end()) {
					bulk_count_ = cfg.at("read_size").get<int>();
				}
			}
			catch (const std::exception& _e) {
				THROW(USER_INPUT_OPTION_ERR, _e.what());
			}
		}
	}; // struct configuration

	std::unique_ptr<configuration> config;
	std::string object_index_policy;
	std::string object_purge_policy;
	std::string metadata_index_policy;
	std::string metadata_purge_policy;

	void apply_document_type_policy(ruleExecInfo_t* _rei,
	                                const std::string& _object_path,
	                                const std::string& _source_resource,
	                                std::string* _document_type)
	{
		std::list<boost::any> args;
		args.push_back(boost::any(_object_path));
		args.push_back(boost::any(_source_resource));
		args.push_back(boost::any(_document_type));
		std::string policy_name =
			irods::indexing::policy::compose_policy_name(irods::indexing::policy::prefix, "document_type_elastic");
		irods::indexing::invoke_policy(_rei, policy_name, args);
	} // apply_document_type_policy

	//void log_fcn(elasticlient::LogLevel, const std::string& _msg)
	//{
		//rodsLog(LOG_DEBUG, "ELASTICLIENT :: [%s]", _msg.c_str());
	//} // log_fcn

	std::string generate_id()
	{
		using namespace boost::archive::iterators;
		std::stringstream os;
		typedef base64_from_binary< // convert binary values to base64 characters
			transform_width<        // retrieve 6 bit integers from a sequence of 8 bit bytes
				const char*,
				6,
				8>>
			base64_text; // compose all the above operations in to a new iterator

		boost::uuids::uuid uuid{boost::uuids::random_generator()()};
		std::string uuid_str = boost::uuids::to_string(uuid);
		std::copy(
			base64_text(uuid_str.c_str()), base64_text(uuid_str.c_str() + uuid_str.size()), ostream_iterator<char>(os));

		return os.str();
	} // generate_id

	std::string get_object_index_id(ruleExecInfo_t* _rei, const std::string& _object_path, bool* iscoll = nullptr)
	{
		boost::filesystem::path p{_object_path};
		std::string coll_name = p.parent_path().string();
		std::string data_name = p.filename().string();
		namespace fs = irods::experimental::filesystem;
		namespace fsvr = irods::experimental::filesystem::server;
		std::string query_str;
		if (fsvr::is_collection(*_rei->rsComm, fs::path{_object_path})) {
			if (iscoll) {
				*iscoll = true;
			}
			query_str = boost::str(boost::format("SELECT COLL_ID WHERE COLL_NAME = '%s'") % _object_path);
		}
		else {
			if (iscoll) {
				*iscoll = false;
			}
			query_str = boost::str(boost::format("SELECT DATA_ID WHERE DATA_NAME = '%s' AND COLL_NAME = '%s'") %
			                       data_name % coll_name);
		}
		try {
			irods::query<rsComm_t> qobj{_rei->rsComm, query_str, 1};
			if (qobj.size() > 0) {
				return qobj.front()[0];
			}
			THROW(CAT_NO_ROWS_FOUND, boost::format("failed to get object id for [%s]") % _object_path);
		}
		catch (const irods::exception& _e) {
			THROW(CAT_NO_ROWS_FOUND, boost::format("failed to get object id for [%s]") % _object_path);
		}

	} // get_object_index_id

	void get_metadata_for_object_index_id(ruleExecInfo_t* _rei,
	                                      std::string _obj_id,
	                                      bool _is_coll,
	                                      std::optional<nlohmann::json>& _out)
	{
		if (!_out || !_out->is_array())
			_out = nlohmann::json::array();
		auto& avus_out = *_out;
		const std::string query_str =
			_is_coll ? fmt::format("SELECT META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE, META_COLL_ATTR_UNITS"
		                           " WHERE COLL_ID = '{}' ",
		                           _obj_id)
					 : fmt::format("SELECT META_DATA_ATTR_NAME, META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS"
		                           " WHERE DATA_ID = '{}' ",
		                           _obj_id);
		irods::query<rsComm_t> qobj{_rei->rsComm, query_str};
		for (const auto& row : qobj) {
			if (row[0] == config->index)
				continue;
			avus_out += {{"attribute", row[0]}, {"value", row[1]}, {"unit", row[2]}};
		}
	} // get_metadata_for_object_index_id

	void update_object_metadata(ruleExecInfo_t* _rei,
	                            const std::string& _object_path,
	                            const std::string& _attribute,
	                            const std::string& _value,
	                            const std::string& _units)
	{
		modAVUMetadataInp_t set_op{.arg0 = "set",
		                           .arg1 = "-d",
		                           .arg2 = const_cast<char*>(_object_path.c_str()),
		                           .arg3 = const_cast<char*>(_attribute.c_str()),
		                           .arg4 = const_cast<char*>(_value.c_str()),
		                           .arg5 = const_cast<char*>(_units.c_str())};

		auto status = rsModAVUMetadata(_rei->rsComm, &set_op);
		if (status < 0) {
			THROW(status, boost::format("failed to update object [%s] metadata") % _object_path);
		}
	} // update_object_metadata

	void invoke_indexing_event_full_text(ruleExecInfo_t* _rei,
	                                     const std::string& _object_path,
	                                     const std::string& _source_resource,
	                                     const std::string& _index_name)
	{
		try {
			if (config->bulk_count_ < 0) {
				// TODO Do we protect against this?
			}

			std::string doc_type{"text"}; // TODO What is this for?
			apply_document_type_policy(_rei, _object_path, _source_resource, &doc_type);

			const std::string object_id = get_object_index_id(_rei, _object_path);
			std::vector<char> buffer(config->read_size_);
			irods::experimental::io::server::basic_transport<char> xport(*_rei->rsComm);
			irods::experimental::io::idstream in{xport, _object_path};

			int chunk_counter{0};
			bool need_final_perform{false};
			std::stringstream ss;

			while (in) {
				in.read(buffer.data(), buffer.size());

				// The indexing instruction.
				ss << json{{"index", {
					{"_id", fmt::format("{}_{}", object_id, chunk_counter++)}
				}}}.dump() << '\n';

				// The defaults for the .dump() member function.
				constexpr int indent = -1;
				constexpr char indent_char = ' ';
				constexpr bool ensure_ascii = false;

				// The data to index.
				// The version of .dump() invoked here instructs the library to ignore
				// invalid UTF-8 sequences. All bytes are copied to the output unchanged.
				ss << json{
					{"absolutePath", _object_path},
					{"data", std::string_view(buffer.data(), in.gcount())}
				}.dump(indent, indent_char, ensure_ascii, json::error_handler_t::ignore) << '\n';

				// TODO Send bulk request if chunk counter has reached bulk limit.
				// Clear the stringstream if the request is sent.
				if (chunk_counter == config->bulk_count_) {
					chunk_counter = 0;
					ss.str("");
					const auto res = send_http_request(config->hosts_[0], http::verb::post, _index_name + "/_bulk", ss.str()); // TODO C++20 supports .view(), but clang 13 doesn't appear to implement it :-(
					(void) res;
					// TODO Check response.
				}
			}

			if (chunk_counter > 0) {
				// TODO Elasticsearch limits the maximum size of a HTTP request to 100mb.
				// See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html.
				const auto res = send_http_request(config->hosts_[0], http::verb::post, _index_name + "/_bulk", ss.str());
				(void) res;
				// TODO Check response.
			}
		}
		catch (const irods::exception& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			auto irods_error = _e.code();
			if (irods_error != CAT_NO_ROWS_FOUND) {
				THROW(irods_error, _e.what());
			}
		}
		catch (const std::runtime_error& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
		catch (const std::exception& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
	} // invoke_indexing_event_full_text

	void invoke_purge_event_full_text(ruleExecInfo_t* _rei,
	                                  const std::string& _object_path,
	                                  const std::string& _source_resource,
	                                  const std::string& _index_name)
	{
		try {
			std::string doc_type{"text"}; // TODO What is this for?
			apply_document_type_policy(_rei, _object_path, _source_resource, &doc_type);

			const std::string object_id{get_object_index_id(_rei, _object_path)};
			int chunk_counter{0};
			bool done{false};

			while (!done) {
				//elasticlient::Client client{config->hosts_};
				// TODO doc_type appeared to be used in place of _doc. But why?
				const auto response = send_http_request(config->hosts_[0], http::verb::delete_, fmt::format("{}/_doc/{}_{}", _index_name, object_id, chunk_counter));
				++chunk_counter;

				if (!response.has_value()) {
					rodsLog(LOG_ERROR, "%s: No response from elasticsearch host.", __func__);
					continue;
				}

				if (response->result_int() != 200) {
					done = true;
					if (response->result_int() == 404) { // meaningful for logging
						rodsLog(LOG_NOTICE, fmt::format("elasticlient 404: no index entry for chunk ({}) of object_id [{}] in index [{}]",
									chunk_counter, object_id, _index_name).c_str());
					}
				}
			}
		}
		catch (const std::runtime_error& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
		catch (const irods::exception& _e) {
			if (_e.code() == CAT_NO_ROWS_FOUND) {
				return;
			}
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
		catch (const std::exception& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
	} // invoke_purge_event_full_text

	std::string get_metadata_index_id(const std::string& _index_id,
	                                  const std::string& _attribute,
	                                  const std::string& _value,
	                                  const std::string& _units)
	{
		std::string str = _attribute + _value + _units;
		irods::Hasher hasher;
		irods::getHasher(irods::MD5_NAME, hasher);
		hasher.update(str);

		std::string digest;
		hasher.digest(digest);

		return _index_id + irods::indexing::indexer_separator + digest;

	} // get_metadata_index_id

	void invoke_indexing_event_metadata(ruleExecInfo_t* _rei,
	                                    const std::string& _object_path,
	                                    const std::string& _attribute,
	                                    const std::string& _value,
	                                    const std::string& _unit,
	                                    const std::string& _index_name,
	                                    nlohmann::json& obj_meta)
	{
		try {
			bool is_coll{};
			auto object_id = get_object_index_id(_rei, _object_path, &is_coll);

			std::optional<nlohmann::json> jsonarray;
			get_metadata_for_object_index_id(_rei, object_id, is_coll, jsonarray);
			if (!jsonarray) {
				irods::log(LOG_WARNING,
				           fmt::format(
							   "In {}, function {}: Aborted indexing metadata, null AVU array returned for object [{}]",
							   __FILE__,
							   __func__,
							   _object_path));
				return;
			}
			obj_meta["metadataEntries"] = *jsonarray;

			//elasticlient::Client client{config->hosts_};
			//const auto target = fmt::format("{}/_doc/{}?op_type=create", index_name, doc_id);
			const auto response = send_http_request(config->hosts_[0], http::verb::put, fmt::format("{}/_doc/{}", _index_name, object_id), obj_meta.dump());

			if (!response.has_value()) {
				THROW(SYS_INTERNAL_ERR,
					  fmt::format("failed to index metadata [{}] [{}] [{}] for [{}]. No response.",
								  _attribute, _value, _unit, _object_path));
			}

			if (response->result_int() != 200 && response->result_int() != 201) {
				THROW(SYS_INTERNAL_ERR,
					  fmt::format("failed to index metadata [{}] [{}] [{}] for [{}] code [{}] message [{}]",
								  _attribute, _value, _unit, _object_path, response->result_int(), response->body()));
			}
		}
		catch (const irods::exception& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			auto irods_error = _e.code();
			if (irods_error != CAT_NO_ROWS_FOUND) {
				THROW(irods_error, _e.what());
			}
		}
		catch (const std::runtime_error& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
		catch (const std::exception& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
	} // invoke_indexing_event_metadata

	void invoke_purge_event_metadata(ruleExecInfo_t* _rei,
	                                 const std::string& _object_path,
	                                 const std::string& _attribute,
	                                 const std::string& _value,
	                                 const std::string& _unit,
	                                 const std::string& _index_name,
	                                 const nlohmann::json& = {})
	{
		try {
			namespace fs = irods::experimental::filesystem;

			// we now accept object id or path here, so pep_api_rm_coll_post can purge
			std::string object_id{fs::path{_object_path}.is_absolute() ? get_object_index_id(_rei, _object_path) : _object_path};

			//elasticlient::Client client{config->hosts_};
			const auto response = send_http_request(config->hosts_[0], http::verb::delete_, fmt::format("{}/_doc/{}", _index_name, object_id));

			if (!response.has_value()) {
				rodsLog(LOG_ERROR, fmt::format("{}: No response from elaticsearch host.", __func__).c_str());
			}

			switch (response->result_int()) {
				// either the index has been deleted, or the AVU was cleared unexpectedly
				case 404:
					rodsLog(LOG_NOTICE, fmt::format("received HTTP status code of 404: no index entry for AVU ({}, {}, {}) on object [{}] in index [{}]", _attribute, _value, _unit, _object_path, _index_name).c_str());
					break;
				// routinely expected return codes ( not logged ):
				case 200:
				case 201:
					break;
				// unexpected return codes:
				default:
					THROW(SYS_INTERNAL_ERR,
					      fmt::format("failed to index metadata [{}] [{}] [{}] for [{}] code [{}] message [{}]",
					          _attribute, _value, _unit, _object_path, response->result_int(), response->body()));
			}
		}
		catch (const std::runtime_error& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
		catch (const std::exception& _e) {
			rodsLog(LOG_ERROR, "Exception [%s]", _e.what());
			THROW(SYS_INTERNAL_ERR, _e.what());
		}
	} // invoke_purge_event_metadata

	irods::error start(irods::default_re_ctx&, const std::string& _instance_name)
	{
		RuleExistsHelper::Instance()->registerRuleRegex("irods_policy_.*");
		config = std::make_unique<configuration>(_instance_name);
		object_index_policy =
			irods::indexing::policy::compose_policy_name(irods::indexing::policy::object::index, "elasticsearch");
		object_purge_policy =
			irods::indexing::policy::compose_policy_name(irods::indexing::policy::object::purge, "elasticsearch");
		metadata_index_policy =
			irods::indexing::policy::compose_policy_name(irods::indexing::policy::metadata::index, "elasticsearch");
		metadata_purge_policy =
			irods::indexing::policy::compose_policy_name(irods::indexing::policy::metadata::purge, "elasticsearch");

		if (getRodsLogLevel() > LOG_NOTICE) {
			//elasticlient::setLogFunction(log_fcn);
		}
		return SUCCESS();
	}

	irods::error stop(irods::default_re_ctx&, const std::string&)
	{
		return SUCCESS();
	}

	irods::error rule_exists(irods::default_re_ctx&, const std::string& _rn, bool& _ret)
	{
		_ret = "irods_policy_recursive_rm_object_by_path" == _rn || object_index_policy == _rn ||
			   object_purge_policy == _rn || metadata_index_policy == _rn || metadata_purge_policy == _rn;
		return SUCCESS();
	}

	irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules)
	{
		_rules.push_back(object_index_policy);
		_rules.push_back(object_purge_policy);
		_rules.push_back(metadata_index_policy);
		_rules.push_back(metadata_purge_policy);
		return SUCCESS();
	}

	irods::error exec_rule(irods::default_re_ctx&,
						   const std::string& _rn,
						   std::list<boost::any>& _args,
						   irods::callback _eff_hdlr)
	{
		ruleExecInfo_t* rei{};
		const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);

		if (!err.ok()) {
			return err;
		}

		using nlohmann::json;
		try {
			if (_rn == object_index_policy) {
				auto it = _args.begin();
				const std::string object_path{boost::any_cast<std::string>(*it)};
				++it;
				const std::string source_resource{boost::any_cast<std::string>(*it)};
				++it;
				const std::string index_name{boost::any_cast<std::string>(*it)};
				++it;

				invoke_indexing_event_full_text(rei, object_path, source_resource, index_name);
			}
			else if (_rn == object_purge_policy) {
				auto it = _args.begin();
				const std::string object_path{boost::any_cast<std::string>(*it)};
				++it;
				const std::string source_resource{boost::any_cast<std::string>(*it)};
				++it;
				const std::string index_name{boost::any_cast<std::string>(*it)};
				++it;

				invoke_purge_event_full_text(rei, object_path, source_resource, index_name);
			}
			else if (_rn == metadata_index_policy || _rn == metadata_purge_policy) {
				auto it = _args.begin();
				const std::string object_path{boost::any_cast<std::string>(*it)};
				++it;
				const std::string attribute{boost::any_cast<std::string>(*it)};
				++it;
				const std::string value{boost::any_cast<std::string>(*it)};
				++it;
				const std::string unit{boost::any_cast<std::string>(*it)};
				++it;
				const std::string index_name{boost::any_cast<std::string>(*it)};
				++it;

				std::string obj_meta_str = "{}";

				if (it != _args.end()) {
					obj_meta_str = boost::any_cast<std::string>(*it++);
				}

				json obj_meta = nlohmann::json::parse(obj_meta_str);

				if (_rn == metadata_purge_policy && attribute.empty()) { //  purge with AVU by name?
					invoke_purge_event_metadata( //  delete the indexed entry
						rei,
						object_path,
						attribute,
						value,
						unit,
						index_name);
				}
				else {
					invoke_indexing_event_metadata( // update the indexed entry
						rei,
						object_path,
						attribute,
						value,
						unit,
						index_name,
						obj_meta);
				}
			}
			else if (_rn == "irods_policy_recursive_rm_object_by_path") {
				auto it = _args.begin();
				const std::string the_path{boost::any_cast<std::string>(*it)};
				std::advance(it, 2);
				const json recurse_info = json::parse(boost::any_cast<std::string&>(*it));

				const auto escaped_path = [p = the_path]() mutable {
					boost::replace_all(p, "\\", "\\\\");
					boost::replace_all(p, "?", "\\?");
					boost::replace_all(p, "*", "\\*");
					return p;
				}();

				std::string JtopLevel = json{{"query", {{"match", {{"absolutePath", escaped_path}}}}}}.dump();
				std::string JsubObject;

				try {
					if (recurse_info["is_collection"].get<bool>()) {
						JsubObject =
							json{{"query", {{"wildcard", {{"absolutePath", {{"value", escaped_path + "/*"}}}}}}}}.dump();
					}
				}
				catch (const std::domain_error& e) {
					// TODO What is this about? Why std::domain_error?
					return ERROR(
						-1, fmt::format("_delete_by_query - stopped short of performRequest - domain_error: {}", e.what()));
				}

				try {
					for (const std::string& index_name : recurse_info["indices"]) {
						for (const std::string& json_out : {JtopLevel, JsubObject}) {
							if (json_out.empty()) {
								continue;
							}

							const auto response = send_http_request(config->hosts_[0], http::verb::post, fmt::format("{}/_delete_by_query", index_name), json_out);

							if (!response.has_value()) {
								rodsLog(LOG_ERROR, fmt::format("{}: No response from elaticsearch host.", __func__).c_str());
								continue;
							}

							if (response->result_int() != 200) {
								rodsLog(LOG_WARNING,
										   fmt::format("_delete_by_query - response code not 200"
													   "\n\t- for path [{}]"
													   "\n\t- escaped as [{}]"
													   "\n\t- json request body is [{}]",
													   the_path,
													   escaped_path,
													   json_out).c_str());
							}
						}
					}
				}
				catch (const nlohmann::json::parse_error& e) {
					rodsLog(LOG_ERROR, fmt::format("JSON parse exception : [{}]", e.what()).c_str());
				}
			} // "irods_policy_recursive_rm_object_by_path"
			else {
				return ERROR(SYS_NOT_SUPPORTED, _rn);
			}
		}
		catch (const std::invalid_argument& _e) {
			irods::indexing::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
			return ERROR(SYS_NOT_SUPPORTED, _e.what());
		}
		catch (const boost::bad_any_cast& _e) {
			irods::indexing::exception_to_rerror(INVALID_ANY_CAST, _e.what(), rei->rsComm->rError);
			return ERROR(SYS_NOT_SUPPORTED, _e.what());
		}
		catch (const irods::exception& _e) {
			irods::indexing::exception_to_rerror(_e, rei->rsComm->rError);
			return irods::error(_e);
		}

		return err;
	} // exec_rule

	irods::error exec_rule_text(irods::default_re_ctx&,
								const std::string&,
								msParamArray_t*,
								const std::string&,
								irods::callback)
	{
		return ERROR(RULE_ENGINE_CONTINUE, "exec_rule_text is not supported");
	} // exec_rule_text

	irods::error exec_rule_expression(irods::default_re_ctx&, const std::string&, msParamArray_t*, irods::callback)
	{
		return ERROR(RULE_ENGINE_CONTINUE, "exec_rule_expression is not supported");
	} // exec_rule_expression
} // namespace

extern "C" irods::pluggable_rule_engine<irods::default_re_ctx>* plugin_factory(const std::string& _inst_name,
                                                                               const std::string& _context)
{
	irods::pluggable_rule_engine<irods::default_re_ctx>* re =
		new irods::pluggable_rule_engine<irods::default_re_ctx>(_inst_name, _context);
	re->add_operation<irods::default_re_ctx&, const std::string&>(
		"start", std::function<irods::error(irods::default_re_ctx&, const std::string&)>(start));
	re->add_operation<irods::default_re_ctx&, const std::string&>(
		"stop", std::function<irods::error(irods::default_re_ctx&, const std::string&)>(stop));
	re->add_operation<irods::default_re_ctx&, const std::string&, bool&>(
		"rule_exists", std::function<irods::error(irods::default_re_ctx&, const std::string&, bool&)>(rule_exists));
	re->add_operation<irods::default_re_ctx&, std::vector<std::string>&>(
		"list_rules", std::function<irods::error(irods::default_re_ctx&, std::vector<std::string>&)>(list_rules));
	re->add_operation<irods::default_re_ctx&, const std::string&, std::list<boost::any>&, irods::callback>(
		"exec_rule",
		std::function<irods::error(
			irods::default_re_ctx&, const std::string&, std::list<boost::any>&, irods::callback)>(exec_rule));
	re->add_operation<irods::default_re_ctx&, const std::string&, msParamArray_t*, const std::string&, irods::callback>(
		"exec_rule_text",
		std::function<irods::error(
			irods::default_re_ctx&, const std::string&, msParamArray_t*, const std::string&, irods::callback)>(
			exec_rule_text));

	re->add_operation<irods::default_re_ctx&, const std::string&, msParamArray_t*, irods::callback>(
		"exec_rule_expression",
		std::function<irods::error(irods::default_re_ctx&, const std::string&, msParamArray_t*, irods::callback)>(
			exec_rule_expression));
	return re;
} // plugin_factory
